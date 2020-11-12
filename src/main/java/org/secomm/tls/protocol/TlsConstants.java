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

public class TlsConstants {

    // Fragment types
    public static final byte CHANGE_CIPHER_SPEC = 20;
    public static final byte ALERT = 21;
    public static final byte HANDSHAKE = 22;
    public static final byte APPLICATION_DATA = 23;

    // Hashing algorithms
    public static final byte DHE_HASH_NONE = 0;
    public static final byte DHE_HASH_MD5 = 1;
    public static final byte DHE_HASH_SHA1 = 2;
    public static final byte DHE_HASH_SHA224 = 3;
    public static final byte DHE_HASH_SHA256 = 4;
    public static final byte DHE_HASH_SHA384 = 5;
    public static final byte DHE_HASH_SHA512 = 6;

    // Signature algorithms
    public static final byte DHE_SIGNATURE_ANONYMOUS = 0;
    public static final byte DHE_SIGNATURE_RSA = 1;
    public static final byte DHE_SIGNATURE_DSA = 2;
    public static final byte DHE_SIGNATURE_ECDSA = 3;


}
