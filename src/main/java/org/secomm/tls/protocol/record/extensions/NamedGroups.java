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

package org.secomm.tls.protocol.record.extensions;

public class NamedGroups {

    /* Elliptic Curve Groups (ECDHE) */
    public static final short secp256r1 = 0x0017;
    public static final short secp384r1 = 0x0018;
    public static final short secp521r1 = 0x0019;
    public static final short x25519 = 0x001D;
    public static final short x448 = 0x001E;

    /* Finite Field Groups (DHE) */
    public static final short ffdhe2048 = 0x0100;
    public static final short ffdhe3072 = 0x0101;
    public static final short ffdhe4096 = 0x0102;
    public static final short ffdhe6144 = 0x0103;
    public static final short ffdhe8192 = 0x0104;

    /* Reserved Code Points
    ffdhe_private_use(0x01FC..0x01FF)
    ecdhe_private_use(0xFE00..0xFEFF)
    */
}
