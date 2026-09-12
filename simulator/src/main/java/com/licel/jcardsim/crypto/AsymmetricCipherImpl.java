// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.crypto.CipherUtils.CipherState;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;

import java.util.function.Supplier;

/*
 * Implementation <code>Cipher</code> with asymmetric keys based
 * on BouncyCastle CryptoAPI.
 * @see Cipher
 */
public final class AsymmetricCipherImpl extends Cipher {

    // algByte 0 is the sentinel for entries with no one-argument ALG_* constant (the OAEP-SHA variants).
    private enum CipherAlg {
        RSA_NOPAD(ALG_RSA_NOPAD, CIPHER_RSA, PAD_NOPAD, RSAEngine::new),
        RSA_PKCS1(ALG_RSA_PKCS1, CIPHER_RSA, PAD_PKCS1, () -> new PKCS1Encoding(new RSAEngine())),
        RSA_OAEP_SHA1(ALG_RSA_PKCS1_OAEP, CIPHER_RSA, PAD_PKCS1_OAEP, () -> new OAEPEncoding(new RSAEngine(), new SHA1Digest())),
        RSA_OAEP_SHA224((byte) 0, CIPHER_RSA, PAD_PKCS1_OAEP_SHA224, () -> new OAEPEncoding(new RSAEngine(), new SHA224Digest())),
        RSA_OAEP_SHA256((byte) 0, CIPHER_RSA, PAD_PKCS1_OAEP_SHA256, () -> new OAEPEncoding(new RSAEngine(), new SHA256Digest())),
        RSA_OAEP_SHA384((byte) 0, CIPHER_RSA, PAD_PKCS1_OAEP_SHA384, () -> new OAEPEncoding(new RSAEngine(), new SHA384Digest())),
        RSA_OAEP_SHA512((byte) 0, CIPHER_RSA, PAD_PKCS1_OAEP_SHA512, () -> new OAEPEncoding(new RSAEngine(), new SHA512Digest()));

        final byte algByte;
        final byte cipher;
        final byte padding;
        final Supplier<AsymmetricBlockCipher> engineFactory;

        CipherAlg(byte algByte, byte cipher, byte padding, Supplier<AsymmetricBlockCipher> engineFactory) {
            this.algByte = algByte;
            this.cipher = cipher;
            this.padding = padding;
            this.engineFactory = engineFactory;
        }

        // Resolves a (cipher, padding) pair to a table entry; null when unrecognised.
        static CipherAlg from(byte cipher, byte padding) {
            for (var c : values()) {
                if (c.cipher == cipher && c.padding == padding) {
                    return c;
                }
            }
            return null;
        }

        // Resolves a one-argument ALG_* byte; null when unrecognised. algByte 0 is never matched here,
        // so the OAEP-SHA variants are reachable only through the (cipher, padding) pair.
        static CipherAlg byByte(byte algorithm) {
            for (var c : values()) {
                if (c.algByte != 0 && c.algByte == algorithm) {
                    return c;
                }
            }
            return null;
        }
    }

    private CipherAlg spec;
    byte algorithm;
    AsymmetricBlockCipher engine;
    CipherState state = CipherState.UNINITIALIZED;
    // Widest input of the largest supported RSA key.
    private static final short MAX_INPUT = (short) (KeyBuilder.LENGTH_RSA_4096 / Byte.SIZE + 1);

    final byte[] buffer;
    // Input length allowed by the current key.
    short bufferLen;
    short bufferPos;

    byte initMode;

    private AsymmetricCipherImpl(CipherAlg s) {
        resolve(s);
        buffer = JCSystem.makeTransientByteArray(MAX_INPUT, JCSystem.CLEAR_ON_RESET);
    }

    public static Cipher getInstance(byte algorithm) {
        CipherAlg s = CipherAlg.byByte(algorithm);
        return s == null ? null : new AsymmetricCipherImpl(s);
    }

    public static Cipher getInstance(byte cipherAlgorithm, byte paddingAlgorithm) {
        CipherAlg s = CipherAlg.from(cipherAlgorithm, paddingAlgorithm);
        return s == null ? null : new AsymmetricCipherImpl(s);
    }

    private void resolve(CipherAlg s) {
        this.spec = s;
        this.algorithm = s.algByte;
        this.engine = s.engineFactory.get();
    }

    @Override
    public void init(Key theKey, byte theMode) throws CryptoException {
        if (theKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(theKey instanceof KeyWithParameters)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        KeyWithParameters key = (KeyWithParameters) theKey;
        initMode = theMode;
        engine.init(theMode == MODE_ENCRYPT, key.getParameters());
        // BouncyCastle reports an encryption input block one byte short of the modulus width.
        bufferLen = (short) (engine.getInputBlockSize() + (theMode == MODE_ENCRYPT && algorithm == ALG_RSA_NOPAD ? 1 : 0));
        bufferPos = 0;
        state = CipherState.INITIALIZED;
    }

    @Override
    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    @Override
    public byte getAlgorithm() {
        return algorithm;
    }

    @Override
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!state.initialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }

        try {
            if (initMode == MODE_ENCRYPT) {
                if ((outBuff.length - outOffset) < engine.getOutputBlockSize()) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_USE);
                }
                if ((inLength - inOffset) > engine.getInputBlockSize() + (algorithm == ALG_RSA_NOPAD ? 1 : 0)) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_USE);
                }
            }
            update(inBuff, inOffset, inLength, outBuff, outOffset);
            if (algorithm == ALG_RSA_NOPAD) {
                if (bufferPos < engine.getInputBlockSize()) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_USE);
                }
            }
            byte[] data = engine.processBlock(buffer, (short) 0, bufferPos);
            short resultLen = (short) data.length;
            // Restores the leading zeros BouncyCastle strips from a modulus-width ALG_RSA_NOPAD block.
            if (algorithm == ALG_RSA_NOPAD && initMode == MODE_DECRYPT && resultLen < bufferLen) {
                short padLen = (short) (bufferLen - resultLen);
                Util.arrayFillNonAtomic(outBuff, outOffset, padLen, (byte) 0x00);
                Util.arrayCopyNonAtomic(data, (short) 0, outBuff, (short) (outOffset + padLen), resultLen);
                return bufferLen;
            }
            Util.arrayCopyNonAtomic(data, (short) 0, outBuff, outOffset, resultLen);
            return resultLen;
        } catch (InvalidCipherTextException | DataLengthException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } finally {
            reset();
        }
        return -1;
    }

    @Override
    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!state.initialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        if (inLength > (bufferLen - bufferPos)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        bufferPos = (short) (bufferPos + Util.arrayCopyNonAtomic(inBuff, inOffset, buffer, bufferPos, inLength));
        // JC 3.2: asymmetric update only buffers input, writes nothing, always returns 0
        return 0;
    }

    private void reset() {
        bufferPos = 0;
    }

    @Override
    public byte getPaddingAlgorithm() {
        return spec.padding;
    }

    @Override
    public byte getCipherAlgorithm() {
        return spec.cipher;
    }
}
