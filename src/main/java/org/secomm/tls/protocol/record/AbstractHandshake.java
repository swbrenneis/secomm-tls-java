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

import org.secomm.tls.util.NumberReaderWriter;

import java.io.IOException;
import java.io.OutputStream;

public abstract class AbstractHandshake implements Handshake {

    protected byte handshakeType;

    /**
     * The handshake message length. This is transmitted
     * as a 24 bit number.
     */
    protected int length;

/*
    protected AbstractHandshake(byte handshakeType, int length) {
        this.handshakeType = handshakeType;
        this.length = length;
    }
*/

    protected AbstractHandshake(byte handshakeType) {
        this.handshakeType = handshakeType;
    }

    protected abstract void calculateHandshakeLength();

    protected void encodeHeader(OutputStream out) throws IOException {

        out.write(handshakeType);
        if (length == 0) {
            calculateHandshakeLength();
        }
        NumberReaderWriter.write24Bit(length, out);
    }

    @Override
    public short getLength() {
        if (length == 0) {
            calculateHandshakeLength();
        }
        return (short) length;
    }
}
