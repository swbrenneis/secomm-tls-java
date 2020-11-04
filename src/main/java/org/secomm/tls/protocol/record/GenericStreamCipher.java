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
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.net.PortUnreachableException;
import java.nio.ByteBuffer;

public class GenericStreamCipher implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<GenericStreamCipher> {
        @Override
        public GenericStreamCipher build() throws InvalidEncodingException, InvalidHandshakeType {
            return new GenericStreamCipher();
        }
    }

    private byte[] content;

    private byte[] mac;

    public GenericStreamCipher() {

    }

    @Override
    public void decode(ByteBuffer buffer) throws IOException {

        short contentLength = NumberReaderWriter.readShort(buffer);
        content = new byte[contentLength];
        buffer.get(content);
        short macLength = NumberReaderWriter.readShort(buffer);
        mac = new byte[macLength];
        buffer.get(mac);
    }

    @Override
    public void encode(OutputStream out) throws IOException {

        NumberReaderWriter.writeShort((short) content.length, out);
        out.write(content);
        NumberReaderWriter.writeShort((short) mac.length, out);
        out.write(mac);
    }

    @Override
    public short getLength() {
        return (short) (2 + content.length + 2 + mac.length);
    }

}
