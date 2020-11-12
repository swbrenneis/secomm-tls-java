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

package org.secomm.tls.protocol;

import java.util.stream.Stream;

public class SignatureAndHashAlgorithm {

    int hashAlgorithm;

    int signatureAlgorithm;

    short algorithm;

    public SignatureAndHashAlgorithm(short algorithm) {
        this.algorithm = algorithm;
        signatureAlgorithm = algorithm & 0xff;
        hashAlgorithm = (algorithm >> 8) & 0xff;
    }

    public int getHashAlgorithm() {
        return hashAlgorithm;
    }

    public int getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getHashAlgorithmString() {
        return null;
    }

    public String getSignatureAlgorithmString() {
        return null;
    }

    public short getAlgorithm() {
        return algorithm;
    }
}
