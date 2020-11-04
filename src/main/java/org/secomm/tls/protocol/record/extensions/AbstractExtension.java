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

package org.secomm.tls.protocol.record.extensions;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public abstract class AbstractExtension implements Extension {

    protected final short extensionType;

    protected byte[] extensionData;

    protected AbstractExtension(short extensionType) {
        this.extensionType = extensionType;
    }

    @Override
    public void encode(OutputStream out) throws IOException {
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        if (extensionData == null) {
            encodeExtensionData();
        }
        NumberReaderWriter.writeShort(extensionType, out);
        NumberReaderWriter.writeShort((short) extensionData.length, out);
        out.write(extensionData);
    }

    protected abstract void encodeExtensionData() throws IOException;

    protected abstract void decodeExtensionData();

    @Override
    public int decode(ByteBuffer buffer) {
        short extensionDataLength = buffer.getShort();
        // Some extensions with have a zero size
        if (extensionDataLength > 0) {
            extensionData = new byte[extensionDataLength];
            buffer.get(extensionData);
            decodeExtensionData();
        }
        return extensionDataLength + 2;
    }

    @Override
    public short getLength() throws IOException {
        if (extensionData == null) {
            encodeExtensionData();
        }
        return (short) extensionData.length;
    }
}
