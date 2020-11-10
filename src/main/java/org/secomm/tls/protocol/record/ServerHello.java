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

import org.secomm.tls.protocol.record.extensions.ExtensionFactory;
import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;
import org.secomm.tls.protocol.record.extensions.KeyShare;
import org.secomm.tls.protocol.record.extensions.TlsExtension;
import org.secomm.tls.util.EncodingByteBuffer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ServerHello implements TlsHandshakeMessage {

    public static final class Builder implements HandshakeMessageFactory.HandshakeBuilder<ServerHello> {
        public ServerHello build() {
            return new ServerHello();
        }
    }

    public static final int SERVER_RANDOM_LENGTH = 32;

    private RecordLayer.ProtocolVersion version;

    private byte[] serverRandom;

    private byte[] sessionId;

    private short cipherSuite;

    private byte compressionMethod;

    private short extensionsLength;

    private List<TlsExtension> tlsExtensions;

    @Override
    public byte[] encode() {
        return new byte[0];
    }

    @Override
    public void decode(EncodingByteBuffer buffer) throws IOException, InvalidExtensionTypeException {

        version = new RecordLayer.ProtocolVersion(buffer.get(), buffer.get());
        serverRandom = new byte[SERVER_RANDOM_LENGTH];
        buffer.get(serverRandom);
        byte sessionIdLength = buffer.get();
        if (sessionIdLength > 0) {
            sessionId = new byte[sessionIdLength];
            buffer.get(sessionId);
        } else {
            sessionId = new byte[0];
        }

        cipherSuite = buffer.getShort();

        compressionMethod = buffer.get();  // Should always be zero.

        // Extensions
        if (buffer.hasRemaining()) {
            tlsExtensions = new ArrayList<>();
            extensionsLength = buffer.getShort();
            if (extensionsLength > 0) {
                int byteCount = 0;
                while (byteCount < extensionsLength) {
                    short extensionType = buffer.getShort();
                    byteCount += 2;
                    TlsExtension tlsExtension = ExtensionFactory.getExtension(extensionType);
                    // There has to be a better way
                    if (tlsExtension instanceof KeyShare) {
                        ((KeyShare) tlsExtension).setKeyShareType(KeyShare.KeyShareType.CLIENT_HELLO);
                    }
                    byteCount += tlsExtension.decode(buffer);
                    tlsExtensions.add(tlsExtension);
                }
            }
        }
    }

    @Override
    public byte getHandshakeType() {
        return HandshakeMessageTypes.SERVER_HELLO;
    }

    public byte[] getServerRandom() {
        return serverRandom;
    }

    public short getCipherSuite() {
        return cipherSuite;
    }
}
