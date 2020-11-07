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

import java.util.ArrayList;
import java.util.List;

/**
 * RFC 8446 Section 4.2.1
 *
 * struct {
 *     select (Handshake.msg_type) {
 *         case client_hello:
 *             ProtocolVersion versions<2..254>;
 *         case server_hello: // And HelloRetryRequest
 *             ProtocolVersion selected_version;
 *     }
 * } SupportedVersions;
 *
 * uint16 ProtocolVersion
 *
 */
public class SupportedVersions extends AbstractTlsExtension{

    public static final class Builder implements ExtensionFactory.ExtensionBuilder<SupportedVersions> {
        @Override
        public SupportedVersions build() {
            return new SupportedVersions();
        }
    }

    enum HandshakeType { CLIENT_HELLO, SERVER_HELLO, HELLO_RETRY }

    public static short TLSv1_2 = 0x0303;

    private HandshakeType handshakeType;

    /**
     * Used during ClientHello
     */
    private List<Short> versions;

    /**
     * Used during ServerHello and HelloRetryRequest
     */
    private short selectedVersion;

    public SupportedVersions() {
        super(Extensions.SUPPORTED_VERSIONS);
        versions = new ArrayList<>();
        versions.add(TLSv1_2);
    }

    public SupportedVersions(List<Short> versions) {
        super(Extensions.SUPPORTED_VERSIONS);
        this.versions = versions;
        handshakeType = HandshakeType.CLIENT_HELLO;
    }

    public SupportedVersions(short selectedVersion) {
        super(Extensions.SUPPORTED_VERSIONS);
        this.selectedVersion = selectedVersion;
        // Could be ServerHello or HelloRetryRequest. Doesn't matter.
        this.handshakeType = HandshakeType.SERVER_HELLO;
    }

    @Override
    protected void encodeExtensionData() {
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(1024);
        switch (handshakeType) {

        }
    }

    @Override
    protected void decodeExtensionData() {

    }

    @Override
    public String getText() throws InvalidEncodingException {
        return null;
    }

    public void setHandshakeType(HandshakeType handshakeType) {
        this.handshakeType = handshakeType;
    }
}
