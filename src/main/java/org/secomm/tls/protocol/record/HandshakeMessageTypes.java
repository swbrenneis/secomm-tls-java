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

package org.secomm.tls.protocol.record;

public class HandshakeMessageTypes {

    public static final byte HELLO_REQUEST = 0;
    public static final byte CLIENT_HELLO = 1;
    public static final byte SERVER_HELLO = 2;
    public static final byte CERTIFICATE = 11;
    public static final byte SERVER_KEY_EXCHANGE  = 12;
    public static final byte CERTIFICATE_REQUEST = 13;
    public static final byte SERVER_HELLO_DONE = 14;
    public static final byte CERTIFICATE_VERIFY = 15;
    public static final byte CLIENT_KEY_EXCHANGE = 16;
    public static final byte FINISHED = 20;
}
