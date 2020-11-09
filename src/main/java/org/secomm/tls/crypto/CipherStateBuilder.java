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

public class CipherStateBuilder {

    private static final Map<Short, SecurityParameters.BulkCipherAlgorithm> cipherAlgorithmMap =
            Stream.of(new Object[][] {
                    { 0x0a, SecurityParameters.BulkCipherAlgorithm.TRIPLEDES },
                    { 0x39, SecurityParameters.BulkCipherAlgorithm.AES }
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (SecurityParameters.BulkCipherAlgorithm) e[1]));

    private static final Map<Short, SecurityParameters.CipherType> cipherTypeMap = Stream.of( new Object[][] {
            { 0x0a, SecurityParameters.CipherType.BLOCK },
            { 0x39, SecurityParameters.CipherType.BLOCK }
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (SecurityParameters.CipherType) e[1]));

    private static final Map<Short, SecurityParameters.MACAlgorithm> macAlgorithmMap = Stream.of(new Object[][] {
            { 0x0a, SecurityParameters.MACAlgorithm.HMAC_SHA1 },
            { 0x39, SecurityParameters.MACAlgorithm.HMAC_SHA1 }
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (SecurityParameters.MACAlgorithm) e[1]));

    private static final Map<Short, Byte> encryptionKeyLengthMap = Stream.of(new Object[][] {
            { 0x39, 160 },
            { 0x39, 256 }
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (Byte) e[1]));

    private static final Map<Short, Byte> macLengthMap = Stream.of(new Object[][] {
            { 0x0a, 160 },
            { 0x39, 160 }
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (Byte) e[1]));

    public static void setSecurityParameters(SecurityParameters parameters, short cipherSuite)
            throws UnknownCipherSuiteException {

        SecurityParameters.BulkCipherAlgorithm algorithm = cipherAlgorithmMap.get(cipherSuite);
        if (algorithm == null) {
            throw new UnknownCipherSuiteException("Cipher suite " + cipherSuite);
        }
        parameters.setBulkCipherAlgorithm(algorithm);
        parameters.setCipherType(cipherTypeMap.get(cipherSuite));
        parameters.setEncryptionKeyLength(encryptionKeyLengthMap.get(cipherSuite));
        parameters.setMacLength(macLengthMap.get(cipherSuite));
    }
}
