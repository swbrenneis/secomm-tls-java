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

package org.secomm.tls.protocol.record.extensions;

import org.secomm.tls.protocol.record.InvalidEncodingException;
import org.secomm.tls.util.EncodingByteBuffer;

/**
 * RFC 5746
 *
 * struct {
 *     opaque renegotiated_connection<0..255>;
 * } RenegotiationInfo;
 */
public class RenegotiationInfo extends AbstractTlsExtension {

    public static final class Builder implements ExtensionFactory.ExtensionBuilder<RenegotiationInfo> {
        @Override
        public RenegotiationInfo build() {
            return new RenegotiationInfo();
        }
    }

    private byte infoLength;

    private byte[] renegotiatedConnection;

    public RenegotiationInfo() {
        super(Extensions.RENEGOTIATION_INFO);
        infoLength = 0;
        renegotiatedConnection = new byte[0];
    }

    public RenegotiationInfo(byte[] renegotiatedConnection) {
        super(Extensions.RENEGOTIATION_INFO);
        this.renegotiatedConnection = renegotiatedConnection;
        infoLength = (byte) renegotiatedConnection.length;
    }

    @Override
    protected void encodeExtensionData() {
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(infoLength + 1);
        buffer.put(infoLength);
        buffer.put(renegotiatedConnection);
        extensionData = buffer.toArray();
    }

    @Override
    protected void decodeExtensionData() {
        EncodingByteBuffer data = EncodingByteBuffer.wrap(extensionData);
        infoLength = data.get();
        renegotiatedConnection = new byte[infoLength];
        data.get(renegotiatedConnection);
    }

    @Override
    public String getText() throws InvalidEncodingException {
        return null;
    }
}
