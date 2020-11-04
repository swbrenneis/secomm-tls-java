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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
 * EXPRESSOR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMEN.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 */

package org.secomm.tls.protocol.record;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public class GenericBlockCipher implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<GenericBlockCipher> {
        @Override
        public GenericBlockCipher build() throws InvalidEncodingException, InvalidHandshakeType {
            return new GenericBlockCipher();
        }
    }

    private byte[] iv;

    private byte[] content;

    private byte[] mac;

    private byte[] padding;

    private byte paddingLength;

    @Override
    public void encode(OutputStream out) throws IOException {

        NumberReaderWriter.writeShort((short) iv.length, out);
        out.write(iv);
        NumberReaderWriter.writeShort((short) content.length, out);
        out.write(content);
        NumberReaderWriter.writeShort((short) mac.length, out);
        out.write(mac);
        out.write(padding);
        out.write(paddingLength);
    }

    @Override
    public short getLength() {
        return (short) (2 + iv.length + 2 + content.length + 2 + mac.length + padding.length + 1);
    }

    @Override
    public void decode(ByteBuffer buffer) throws IOException, InvalidHandshakeType, InvalidEncodingException {

        // Hmmm
    }
}
