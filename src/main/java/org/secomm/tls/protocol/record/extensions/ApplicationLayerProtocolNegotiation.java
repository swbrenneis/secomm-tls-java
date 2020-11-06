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
 * RFC 7301
 *
 */
public class ApplicationLayerProtocolNegotiation extends AbstractTlsExtension {

    public static final class Builder implements ExtensionFactory.ExtensionBuilder<ApplicationLayerProtocolNegotiation> {
        @Override
        public ApplicationLayerProtocolNegotiation build() {
            return new ApplicationLayerProtocolNegotiation();
        }
    }

    private byte[] protocolNameList;

    public ApplicationLayerProtocolNegotiation() {
        super(Extensions.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        protocolNameList = new byte[0];
    }

    public ApplicationLayerProtocolNegotiation(byte[] protocolNameList) {
        super(Extensions.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        this.protocolNameList = protocolNameList;
    }

    @Override
    protected void encodeExtensionData() {
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(protocolNameList.length + 2);
        buffer.putShort((short) protocolNameList.length);
        buffer.put(protocolNameList);
        extensionData = buffer.toArray();
    }

    @Override
    protected void decodeExtensionData() {
        EncodingByteBuffer data = EncodingByteBuffer.wrap(extensionData);
        short nameLength = data.getShort();
        protocolNameList = new byte[nameLength];
        data.get(protocolNameList);
    }

    @Override
    public String getText() throws InvalidEncodingException {
        return null;
    }
}
