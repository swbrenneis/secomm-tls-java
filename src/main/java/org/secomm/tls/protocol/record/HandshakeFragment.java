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

import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;
import org.secomm.tls.util.NumberReaderWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class HandshakeFragment implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<HandshakeFragment> {
        public HandshakeFragment build() throws InvalidHandshakeType {
            return new HandshakeFragment();
        }
    }

    private byte handshakeType;

    private Handshake handshake;

    public HandshakeFragment(byte handshakeType, AbstractHandshake handshake) {
        this.handshakeType = handshakeType;
        this.handshake = handshake;
    }

    public HandshakeFragment() {
    }

    @Override
    public void decode(ByteBuffer handshakeBuffer)
            throws InvalidHandshakeType, IOException, InvalidExtensionTypeException {
        
        handshakeType = handshakeBuffer.get();
//        int handshakeLength = NumberReaderWriter.read24Bit(handshakeBuffer);
        handshake = HandshakeContentFactory.getHandshake(handshakeType);
        int wrong = NumberReaderWriter.read24Bit(handshakeBuffer);
        // Firefox sends the wrong handshake length. It should be the total
        // record size - 4. Handshake type + 24 bit length. It sends total
        // record size - 3.
        int handshakeLength = handshakeBuffer.array().length - 4;
        byte[] bytes = new byte[handshakeLength];
        handshakeBuffer.get(bytes);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        handshake.decode(buffer);
    }

    @Override
    public void encode(OutputStream out) throws IOException {
        out.write(handshakeType);
        NumberReaderWriter.write24Bit(handshake.getLength(), out);
        handshake.encode(out);
    }

    @Override
    public short getLength() {
        return (short) (handshake.getLength() + 4);
    }

    public Handshake getHandshake() {
        return handshake;
    }
}
