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

import org.secomm.tls.protocol.record.extensions.Extension;
import org.secomm.tls.protocol.record.extensions.ExtensionFactory;
import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;
import org.secomm.tls.util.NumberReaderWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;

public class ClientHello extends AbstractHandshake {

    public static final class Builder implements HandshakeContentFactory.HandshakeBuilder<ClientHello> {
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

    private List<Extension> extensions;

    public ClientHello() {
        super(HandshakeTypes.CLIENT_HELLO);

        // This may or may not get set later.
        sessionId = new byte[0];
        cipherSuites = new ArrayList<>();
        extensions = new ArrayList<>();
        version = RecordLayer.TLS_1_2;
        compressionMethods = new byte[1];
    }

    @Override
    public void decode(ByteBuffer buffer) throws IOException, InvalidExtensionTypeException {

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
        short cipherSuitesLength = NumberReaderWriter.readShort(buffer);
        cipherSuites = new ArrayList<>();
        while (cipherSuites.size() < cipherSuitesLength / 2) {
            cipherSuites.add(NumberReaderWriter.readShort(buffer));
        }

        // Compression method
        compressionMethodLength = buffer.get();
        if (compressionMethodLength > 0) {
            compressionMethods = new byte[compressionMethodLength];
            buffer.get(compressionMethods);
        }

        // Extensions
        extensions = new ArrayList<>();
        extensionsLength = NumberReaderWriter.readShort(buffer);
        if (extensionsLength > 0) {
            int byteCount = 0;
            while (byteCount < extensionsLength) {
                short extensionType = NumberReaderWriter.readShort(buffer);
                Extension extension = ExtensionFactory.getExtension(extensionType);
                byteCount += extension.decode(buffer);
                extensions.add(ExtensionFactory.getExtension(extensionType));
            }
        }
    }

    @Override
    public void encode(OutputStream out) throws IOException {

        out.write(version.majorVersion);
        out.write(version.minorVersion);
        out.write(clientRandom);
        out.write((byte) sessionId.length);
        if (sessionId.length > 0) {
            out.write(sessionId);
        }
        NumberReaderWriter.writeShort((short) (cipherSuites.size() * 2), out);
        for (Short cipherSuite : cipherSuites) {
            NumberReaderWriter.writeShort(cipherSuite, out);
        }
        out.write(compressionMethods.length);
        if (compressionMethods.length > 0) {
            out.write(compressionMethods);
        }

        if (extensions == null) {
            extensions = ExtensionFactory.getCurrentExtensions();
        }
        NumberReaderWriter.writeShort((short) extensions.size(), out);
        for (Extension extension : extensions) {
            extension.encode(out);
        }
    }

    @Override
    protected void calculateHandshakeLength() {
        length = 2 + 32 + 2;                        // version + clientRandom + sessionId length
        length += sessionId.length;
        length += 2 + (cipherSuites.size() * 2);    // Cipher suitelength + cipher suites
        length += 1 + 1;                            // Compression method
        if (extensions.size() > 0) {
            extensionsLength = 0;
            for (Extension extension : extensions) {
                try {
                    extensionsLength += extension.getLength();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        length += 2 + extensionsLength;             // Extensions length + extension lengths
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

}
