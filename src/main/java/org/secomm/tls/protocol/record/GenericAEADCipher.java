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

public class GenericAEADCipher implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<GenericAEADCipher> {
        @Override
        public GenericAEADCipher build() throws InvalidEncodingException, InvalidHandshakeType {
            return new GenericAEADCipher();
        }
    }

    private byte[] nonceExplicit;

    private byte[] content;

    @Override
    public void encode(OutputStream out) throws IOException {

        NumberReaderWriter.writeShort((short) nonceExplicit.length, out);
        out.write(nonceExplicit);
        NumberReaderWriter.writeShort((short) content.length, out);
        out.write(content);
    }

    @Override
    public short getLength() {
        return (short) (2 + nonceExplicit.length + 2 + content.length);
    }

    @Override
    public void decode(ByteBuffer buffer) throws IOException, InvalidHandshakeType, InvalidEncodingException {

    }
}
