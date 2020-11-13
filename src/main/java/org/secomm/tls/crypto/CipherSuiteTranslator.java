/*
 * Copyright (c) 2020 Steve Brenneis.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following
 * conditions: The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMEN. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 */

package org.secomm.tls.crypto;

import org.secomm.tls.protocol.SecurityParameters;
import org.secomm.tls.protocol.UnknownCipherSuiteException;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CipherSuiteTranslator {

    public enum KeyExchangeAlgorithm { DH_ANON, DHE_RSA, DHE_DSS, RSA, DH_RSA, DH_DSS }

    private static KeyExchangeAlgorithm keyExchangeAlgorithm;

    private static final Map<Short, String> cipherAlgorithmMap =
            Stream.of(new Object[][] {
                    { (short) 0x0a, "TRIPLEDES" },
                    { (short) 0x33, "AES" },
                    { (short) 0x39, "AES" },
                    { (short) 0x9c, "AES"}
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (String) e[1]));

    private static final Map<Short, String> cipherTypeMap = Stream.of( new Object[][] {
            { (short) 0x0a, "BLOCK" },
            { (short) 0x33, "BLOCK" },
            { (short) 0x39, "BLOCK" },
            { (short) 0x9c, "AEAD"}
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (String) e[1]));

    private static final Map<Short, String> macAlgorithmMap = Stream.of(new Object[][] {
            { (short) 0x0a, "HMAC_SHA1" },
            { (short) 0x33, "HMAC_SHA1" },
            { (short) 0x39, "HMAC_SHA1" },
            { (short) 0x9c, "HMAC_SHA256"}
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (String) e[1]));

    private static final Map<Short, String> keyExchangeAlgorithmMap = Stream.of(new Object[][] {
            { (short) 0x0a, KeyExchangeAlgorithm.DH_ANON.toString() },
            { (short) 0x33, KeyExchangeAlgorithm.DHE_RSA.toString() },
            { (short) 0x39, KeyExchangeAlgorithm.DHE_RSA.toString() },
            { (short) 0x9c, KeyExchangeAlgorithm.RSA.toString() }
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (String) e[1]));

    private static final Map<Short, Byte> encryptionKeyLengthMap = Stream.of(new Object[][] {
            { (short) 0x0a, (byte) 160 },
            { (short) 0x33, (byte) 128 },
            { (short) 0x39, (byte) 256 },
            { (short) 0x9c, (byte) 128 }
    }).collect(Collectors.toMap(e -> (short) e[0], e -> (byte) e[1]));

    private static final Map<Short, Byte> macLengthMap = Stream.of(new Object[][] {
            { (short) 0x0a, (byte) 160 },
            { (short) 0x33, (byte) 160 },
            { (short) 0x39, (byte) 160 },
            { (short) 0x9c, (byte) 256 }
    }).collect(Collectors.toMap(e -> (short) e[0], e -> (byte) e[1]));

    public static void setSecurityParameters(SecurityParameters parameters, short cipherSuite)
            throws UnknownCipherSuiteException {

        String algorithm = cipherAlgorithmMap.get(cipherSuite);
        if (algorithm == null) {
            throw new UnknownCipherSuiteException("Cipher suite " + cipherSuite);
        }
        parameters.setBulkCipherAlgorithm(algorithm);
        parameters.setCipherType(cipherTypeMap.get(cipherSuite));

        parameters.setEncryptionKeyLength(encryptionKeyLengthMap.get(cipherSuite));
        parameters.setMacLength(macLengthMap.get(cipherSuite));

        keyExchangeAlgorithm = getKeyExchangeAlgorithm(cipherSuite);
    }

    /**
     * This really stupid function gets around the fact that you
     * can't have a map of enums in Java
     *
     * @param cipherSuite
     * @return
     */
    public static KeyExchangeAlgorithm getKeyExchangeAlgorithm(short cipherSuite) {
        String algorithm = keyExchangeAlgorithmMap.get(cipherSuite);
        if (algorithm != null) {
            return KeyExchangeAlgorithm.valueOf(algorithm);
        } else {
            return null;
        }
    }

    public static KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        return keyExchangeAlgorithm;
    }
}

