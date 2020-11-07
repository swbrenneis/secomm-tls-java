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

import org.apache.commons.io.IOUtils;
import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;
import org.secomm.tls.util.EncodingByteBuffer;
import org.secomm.tls.util.NumberReaderWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public class TlsPlaintextRecord extends TlsRecord {

    public TlsPlaintextRecord(byte contentType, RecordLayer.ProtocolVersion version) {
        super(contentType, version);
    }

    public TlsPlaintextRecord() {
    }

    public void decode(InputStream in) throws RecordLayerException, IOException {

        EncodingByteBuffer recordBuffer = EncodingByteBuffer.wrap(IOUtils.toByteArray(in));
        if (recordBuffer.hasRemaining()) {
            contentType = recordBuffer.get();
            version = new RecordLayer.ProtocolVersion(recordBuffer.get(), recordBuffer.get());
            fragment = ContentFactory.getContent(contentType);
            short length = recordBuffer.getShort();
            byte[] fragmentBytes = new byte[length];
            recordBuffer.get(fragmentBytes);
            EncodingByteBuffer fragmentBuffer = EncodingByteBuffer.wrap(fragmentBytes);
            fragment.decode(fragmentBuffer);
        }
    }

    public byte[] encode() {
        byte[] fragmentBytes = fragment.encode();
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(fragmentBytes.length + 5);
        buffer.put(contentType);
        buffer.put(version.majorVersion);
        buffer.put(version.minorVersion);
        buffer.putShort((short) fragmentBytes.length);
        buffer.put(fragmentBytes);
        return buffer.toArray();
    }

}
