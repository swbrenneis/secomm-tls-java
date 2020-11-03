package org.secomm.tls.protocol.record;

import org.secomm.tls.protocol.record.extensions.ServerNameIndicationExtension;
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

    private List<ServerNameIndicationExtension> extensions;

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
    public void decode(ByteBuffer buffer) throws IOException {

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
                short extensionDataLength = NumberReaderWriter.readShort(buffer);
                byte[] extensionData = new byte[extensionDataLength];
                buffer.get(extensionData);
//                extensions.add(new ServerNameIndicationExtension(extensionType));
                byteCount += extensionDataLength + 4;
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
        NumberReaderWriter.writeShort(extensionsLength, out);
        for (ServerNameIndicationExtension extension : extensions) {
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
/*
            for (ServerNameIndicationExtension extension : extensions) {
                extensionsLength += extension.getLength();
            }
*/
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

    public void setCompressionMethodLength(byte compressionMethodLength) {
        this.compressionMethodLength = compressionMethodLength;
    }

    public void setExtensions(List<ServerNameIndicationExtension> extensions) {
        this.extensions = extensions;
    }

}
