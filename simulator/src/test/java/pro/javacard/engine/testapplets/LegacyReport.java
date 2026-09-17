// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.engine.testapplets;

import javacard.framework.*;

// 16-bit readings via getAvailableMemory(byte), saturated at 32767
final class LegacyReport implements MemoryApplet.Report {
    private static final byte[] TYPES = {JCSystem.MEMORY_TYPE_PERSISTENT, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT};

    @Override
    public short extract(byte[] dst, short offset) {
        short i = 0;
        // step: Three readings
        while (i < TYPES.length) {
            // step: One reading
            Util.setShort(dst, (short) (offset + 2 * i), JCSystem.getAvailableMemory(TYPES[i]));
            i++;
        }
        return 6;
    }

    @Override
    public void gc() {
        // step: A refused request surfaces as SystemException
        try {
            JCSystem.requestObjectDeletion();
        } catch (SystemException e) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
    }
}
