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

package org.secomm.tls.crypto.digest;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

/**
 * For whatever reason, Bouncycastle decided that their SHA1Digest class
 * would not implement their Digest interface. So, we need a proxy class
 * so that other Tls and Bouncycastle classes will work.
 */
public class SHA1DigestWrapper implements Digest {

    public static final class Builder implements DigestFactory.DigestBuilder<SHA1DigestWrapper> {
        public SHA1DigestWrapper build() {
            return new SHA1DigestWrapper();
        }
    }

    private final SHA1Digest digest;

    public SHA1DigestWrapper() {
        digest = new SHA1Digest();
    }

    @Override
    public String getAlgorithmName() {
        return digest.getAlgorithmName();
    }

    @Override
    public int getDigestSize() {
        return digest.getDigestSize();
    }

    @Override
    public void update(byte in) {
        digest.update(in);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        digest.update(in, inOff, len);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        return digest.doFinal(out, outOff);
    }

    @Override
    public void reset() {
        digest.reset();
    }
}
