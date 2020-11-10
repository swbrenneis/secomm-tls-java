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

import org.secomm.tls.util.EncodingByteBuffer;

import java.io.IOException;
import java.nio.ByteBuffer;

public class GenericAEADCipher implements TlsFragment {

    public static final class Builder implements FragmentFactory.FragmentBuilder<GenericAEADCipher> {
        @Override
        public GenericAEADCipher build() throws InvalidEncodingException, InvalidHandshakeMessageType {
            return new GenericAEADCipher();
        }
    }

    private byte[] nonceExplicit;

    private byte[] content;

    @Override
    public byte[] encode() {

        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.putShort((short) nonceExplicit.length);
        buffer.put(nonceExplicit);
        buffer.putShort((short) content.length);
        buffer.put(content);
        return buffer.array();
    }

    @Override
    public void decode(EncodingByteBuffer buffer) throws IOException, InvalidHandshakeMessageType, InvalidEncodingException {

    }

    @Override
    public byte getFragmentType() {
        return 0;
    }
}
