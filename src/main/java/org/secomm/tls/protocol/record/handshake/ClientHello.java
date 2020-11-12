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

package org.secomm.tls.protocol.record.handshake;

import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.extensions.KeyShare;
import org.secomm.tls.protocol.record.extensions.TlsExtension;
import org.secomm.tls.protocol.record.extensions.ExtensionFactory;
import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;
import org.secomm.tls.util.EncodingByteBuffer;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;

public class ClientHello implements TlsHandshakeMessage {

    public static final class Builder implements HandshakeMessageFactory.HandshakeBuilder<ClientHello> {
        public ClientHello build() { return new ClientHello(); }
    }

    public static final int CLIENT_RANDOM_LENGTH = 32;

    private RecordLayer.ProtocolVersion version;

    private byte[] clientRandom;

    private byte[] sessionId;

    private List<Short> cipherSuites;

    private byte compressionMethodLength;

    private byte[] compressionMethods;

    private short extensionsLength;

    private List<TlsExtension> tlsExtensions;

    public ClientHello() {
        // This may or may not get set later.
        version = RecordLayer.TLS_1_2;
        compressionMethods = new byte[1];
    }

    @Override
    public void decode(EncodingByteBuffer buffer) throws IOException, InvalidExtensionTypeException {

        // Version
        version = new RecordLayer.ProtocolVersion(buffer.get(), buffer.get());

        // Client random
        clientRandom = new byte[CLIENT_RANDOM_LENGTH];
        buffer.get(clientRandom);

        // Session ID
        byte sessionIdLength = buffer.get();
        if (sessionIdLength > 0) {
            sessionId = new byte[sessionIdLength];
            buffer.get(sessionId);
        }

        // Cipher suites
        short cipherSuitesLength = buffer.getShort();
        cipherSuites = new ArrayList<>();
        while (cipherSuites.size() < cipherSuitesLength / 2) {
            cipherSuites.add(buffer.getShort());
        }

        // Compression method
        compressionMethodLength = buffer.get();
        if (compressionMethodLength > 0) {
            compressionMethods = new byte[compressionMethodLength];
            buffer.get(compressionMethods);
        }

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
    public byte[] encode() {

        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(1024);
        buffer.put(version.majorVersion);
        buffer.put(version.minorVersion);
        buffer.put(clientRandom);

        if (sessionId != null) {
            buffer.put((byte) sessionId.length);
            if (sessionId.length > 0) {
                buffer.put(sessionId);
            }
        } else {
            buffer.put((byte) 0);
        }

        buffer.putShort((short) (cipherSuites.size() * 2));
        for (Short cipherSuite : cipherSuites) {
            buffer.putShort(cipherSuite);
        }

        buffer.put((byte) compressionMethods.length);
        if (compressionMethods.length > 0) {
            buffer.put(compressionMethods);
        }

        EncodingByteBuffer extensionsBuffer = EncodingByteBuffer.allocate(1024);
        for (TlsExtension tlsExtension : tlsExtensions) {
            byte [] extensionBytes = tlsExtension.encode();
            extensionsLength += extensionBytes.length;
            extensionsBuffer.putShort((short) extensionBytes.length);
            extensionsBuffer.put(extensionBytes);
        }
        byte[] extensionBytes = extensionsBuffer.toArray();
        buffer.putShort((short) extensionBytes.length);
        buffer.put(extensionBytes);
        return buffer.toArray();
    }

    @Override
    public byte getHandshakeType() {
        return HandshakeMessageTypes.CLIENT_HELLO;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public void setClientRandom(byte[] clientRandom) {
        if (clientRandom.length != CLIENT_RANDOM_LENGTH) {
            throw new InvalidParameterException("Invalid client random size");
        }
        this.clientRandom = clientRandom;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    public void setCipherSuites(List<Short> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public void setExtensions(List<TlsExtension> tlsExtensions) {
        this.tlsExtensions = tlsExtensions;
    }
}
