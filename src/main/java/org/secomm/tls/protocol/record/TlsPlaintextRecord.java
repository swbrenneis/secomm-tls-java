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
import java.io.Reader;
import java.nio.ByteBuffer;

public class TlsPlaintextRecord extends TlsRecord {

    public TlsPlaintextRecord(byte contentType, RecordLayer.ProtocolVersion version) {
        super(contentType, version);
    }

    public TlsPlaintextRecord() {
    }

    public void decode(Reader in)
            throws InvalidContentTypeException, InvalidEncodingException, InvalidHandshakeType, IOException,
            InvalidExtensionTypeException {

        byte[] headerBytes = new byte[5];
        NumberReaderWriter.readBytes(headerBytes, in);
        ByteBuffer headerBuffer = ByteBuffer.wrap(headerBytes);
        contentType = headerBuffer.get();
        version = new RecordLayer.ProtocolVersion(headerBuffer.get(), headerBuffer.get());
        short length = headerBuffer.getShort();
        fragment = ContentFactory.getContent(contentType);
        byte[] fragmentBytes = new byte[length];
        NumberReaderWriter.readBytes(fragmentBytes, in);
        ByteBuffer fragmentBuffer = ByteBuffer.wrap(fragmentBytes);
        fragment.decode(fragmentBuffer);
    }

    public void encode(OutputStream out) throws IOException {

        out.write(contentType);
        out.write(version.majorVersion);
        out.write(version.minorVersion);
        NumberReaderWriter.writeShort(fragment.getLength(), out);
        fragment.encode(out);
    }

}
