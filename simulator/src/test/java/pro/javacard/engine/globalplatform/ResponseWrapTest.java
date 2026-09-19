// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPRegistryEntry.ISDLifeCycle;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import java.util.EnumSet;

import static org.testng.Assert.assertEquals;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// wrap() is the applet's job: append SW, wrap(), send. JCRE concatenates data||SW and must not
// wrap again. Double-wrap made gp-pro reject data-bearing R-MAC responses as invalid RMAC while
// empty 9000 still passed (the engine had wrapped those once).
public class ResponseWrapTest {

    private static final AID PKG = AIDUtil.create("010203040506070809");
    private static final AID APP = AIDUtil.create("01020304050607080901");

    // payload chosen so R-ENCRYPTION pad80 is visible: 8 bytes -> one 16-byte block.
    private static final byte[] PAYLOAD = new byte[]{
            (byte) 0xA5, (byte) 0xA5, (byte) 0xA5, (byte) 0xA5,
            (byte) 0xA5, (byte) 0xA5, (byte) 0xA5, (byte) 0xA5
    };

    @DataProvider(name = "responseModes")
    public static Object[][] responseModes() {
        return new Object[][] {
                // C-MAC only: wrap() is a no-op, raw response is data||SW
                {"SCP03-S16-MAC", new SCPConfig.SCP03(true), EnumSet.of(GPSession.APDUMode.MAC), 0, false},
                {"SCP03-S8-RMAC", new SCPConfig.SCP03(), EnumSet.of(GPSession.APDUMode.RMAC), 8, false},
                {"SCP03-S16-RMAC", new SCPConfig.SCP03(true), EnumSet.of(GPSession.APDUMode.RMAC), 16, false},
                {"SCP03-S16-RENC", new SCPConfig.SCP03(true), EnumSet.of(GPSession.APDUMode.RENC), 16, true}
        };
    }

    @Test(dataProvider = "responseModes")
    public void appletWrapSendUnwrappedOnce(String name, SCPConfig cfg, EnumSet<GPSession.APDUMode> mode,
                                           int maclen, boolean renc) throws Exception {
        var sim = engine(cfg);
        try (var bibo = sim.connect()) {
            openIsd(bibo).installAndMakeSelectable(gpAID(PKG), gpAID(PKG), gpAID(APP),
                    EnumSet.noneOf(Privilege.class), new byte[0]);
        }
        try (var bibo = sim.connect()) {
            var rec = new RecordingBIBO(bibo);
            var gp = GPSession.connect(rec, gpAID(APP));
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, mode);
            // EXTERNAL AUTHENTICATE is not wrap()'d (Amd D v1.2 6.2.5); R-MAC is not active yet.
            assertBareSw(rec, 0x9000);

            var data = gp.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_WRAP_ECHO, 0x00, 0x00, PAYLOAD, 256));
            assertEquals(data.getSW(), 0x9000);
            assertEquals(data.getData(), PAYLOAD);
            assertWrappedOnce(rec, PAYLOAD.length, maclen, renc);

            var empty = gp.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_WRAP_ECHO, 0x00, 0x00, 256));
            assertEquals(empty.getSW(), 0x9000);
            assertEquals(empty.getData().length, 0);
            assertWrappedOnce(rec, 0, maclen, renc);

            var err = gp.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_WRAP_ECHO, 0x01, 0x00, 256));
            assertEquals(err.getSW(), 0x6A80);
            assertBareSw(rec, 0x6A80);
        }
    }

    @Test(dataProvider = "responseModes")
    public void isdWrapSendUnwrappedOnce(String name, SCPConfig cfg, EnumSet<GPSession.APDUMode> mode,
                                        int maclen, boolean renc) throws Exception {
        var sim = new JavaCardEngine.Builder().withSCP(cfg).build();
        try (var bibo = sim.connect()) {
            var rec = new RecordingBIBO(bibo);
            var gp = GPSession.discover(rec);
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, mode);
            assertBareSw(rec, 0x9000);

            // GET DATA 9F7F: wrap()+send of 45-byte CPLC. Double-wrap would fail gp-pro R-MAC check.
            var cplc = gp.transmit(new CommandAPDU(0x80, 0xCA, 0x9F, 0x7F, 256));
            assertEquals(cplc.getSW(), 0x9000);
            assertEquals(cplc.getData().length, 45);
            assertWrappedOnce(rec, 45, maclen, renc);

            // SET STATUS empty 9000 still needs wrap() when R-MAC is on.
            gp.setCardStatus(ISDLifeCycle.INITIALIZED);
            assertWrappedOnce(rec, 0, maclen, renc);

            // Error SWs are not wrap()'d (Amd D v1.2 6.2.5).
            var unknown = gp.transmit(new CommandAPDU(0x80, 0xCA, 0x12, 0x34, 256));
            assertEquals(unknown.getSW(), 0x6A88);
            assertBareSw(rec, 0x6A88);
        }
    }

    private static JavaCardEngine engine(SCPConfig cfg) {
        var sim = new JavaCardEngine.Builder().withSCP(cfg).build();
        sim.loadApplet(PKG, PKG, GlobalPlatformTestApplet.class);
        return sim;
    }

    // One R-MAC (and optional R-ENC pad), then SW. A second wrap() would add another MAC and
    // gp-pro would reject the response as invalid RMAC.
    private static void assertWrappedOnce(RecordingBIBO rec, int plain, int maclen, boolean renc) {
        int body = (renc && plain > 0) ? ((plain / 16) + 1) * 16 : plain;
        assertEquals(new ResponseAPDU(rec.last).getSW(), 0x9000);
        assertEquals(rec.last.length, body + maclen + 2);
    }

    private static void assertBareSw(RecordingBIBO rec, int sw) {
        assertEquals(rec.last.length, 2);
        assertEquals(new ResponseAPDU(rec.last).getSW(), sw);
    }

    // Captures the last APDU the card returned so tests can see the R-MAC trailer gp-pro unwraps.
    static final class RecordingBIBO implements BIBO {
        private final BIBO inner;
        byte[] last;

        RecordingBIBO(BIBO inner) {
            this.inner = inner;
        }

        @Override
        public byte[] transceive(byte[] commandAPDU) {
            last = inner.transceive(commandAPDU);
            return last;
        }
    }
}
