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

import java.security.InvalidParameterException;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Algorithms {

    public interface PrfBuilder <T extends PRFAlgorithm> {
        public T build();
    }

    public enum PrfAlgorithms { TLS_PRF_SHA256 }

    public static Map<PrfAlgorithms, PrfBuilder<?>> prfAlgorithms = Stream.of( new Object[][] {
            { PrfAlgorithms.TLS_PRF_SHA256 , new TlsPrfSha256.Builder() }
    }).collect(Collectors.toMap(e -> (PrfAlgorithms) e[0], e -> (PrfBuilder<?>) e[1]));

    public static <T extends PRFAlgorithm> T getPrfAlgorithm(PrfAlgorithms algorithm)
            throws InvalidParameterException {
        if (!prfAlgorithms.containsKey(algorithm)) {
            throw new InvalidParameterException("Unknown PRF algorithm identifier");
        }
        return (T) prfAlgorithms.get(algorithm).build();
    }

    public enum BulkCipherAlgorithm { NULL, RC4, TRIPLE_DES, AES }

    public enum CipherType { STREAM, BLOCK, AEAD }

    public enum MACAlgorithm{ NULL, HMAC_MD5, HMAC_SHA1, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512 }


}
