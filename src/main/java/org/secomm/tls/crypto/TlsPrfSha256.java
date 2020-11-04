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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public class TlsPrfSha256 implements PRFAlgorithm {

    public static final class Builder implements Algorithms.PrfBuilder<TlsPrfSha256> {
        @Override
        public TlsPrfSha256 build() {
            return new TlsPrfSha256();
        }
    }


    @Override
    public byte[] generateRandomBytes(String label, byte[] seed, int length) {
//        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return new byte[0];
    }

    /**
     * Phase 1 of the P_hash algorithm. Creates the first HMAC digest.
     *
     * The form is P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed),
     *                                    HMAC_hash(secret, A(2) + seed),
     *                                    HMAC_hash(secret, A(3) + seed), ...
     *
     *  Where A(0) = seed
     *        A(i) = HMAC_hash(secret, A(i-1))
     *
     *  seed = label + seed
     *
     * @param digest
     * @param label
     * @param seed
     * @param length
     * @return
     */
/*
    private byte[] doPHash(Digest digest, String label, byte[] seed, int length) {

        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(secret));
        hmac.update(label.getBytes(StandardCharsets.UTF_8), 0, label.length());
        hmac.update(seed, 0, seed.length);
        byte[] intermediate = new byte[hmac.getMacSize()];
        hmac.doFinal(intermediate, 0);

        if (intermediate.length < length) {
            return doPHash(digest, intermediate, seed, length);
        } else {
            return Arrays.copyOf(intermediate, length);
        }
    }

*/
    /**
     * Recursive hash until length bytes are generated.
     *
     * @param digest
     * @param previous
     * @param seed
     * @param length
     * @return
     */
/*
    private byte[] doPHash(Digest digest, byte[] previous, byte[] seed, int length) {

        digest.reset();
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(secret));
        hmac.update(previous, 0, previous.length);
        hmac.update(seed, 0, seed.length);
        byte[] intermediate = new byte[hmac.getMacSize()];
        hmac.doFinal(intermediate, 0);

        byte [] result = Arrays.concatenate(previous, intermediate);

        if (result.length < length) {
            return doPHash(digest, result, seed, length);
        } else {
            return Arrays.copyOf(result, length);
        }
    }
*/
}
