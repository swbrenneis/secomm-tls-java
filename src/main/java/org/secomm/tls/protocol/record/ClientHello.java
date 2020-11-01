package org.secomm.tls.protocol.record;

import org.secomm.tls.protocol.record.extensions.HelloExtension;

import java.nio.ByteBuffer;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;

public class ClientHello extends AbstractHandshake {

    public static final class Builder implements HandshakeContentFactory.HandshakeBuilder<ClientHello> {
        public ClientHello build(byte[] encoding) { return new ClientHello(encoding); }
    }

    public static final int CLIENT_RANDOM_LENGTH = 32;

    private RecordLayer.ProtocolVersion version;

    private byte[] clientRandom;

    private byte[] sessionId;

    private List<Short> cipherSuites;

    private byte compressionMethod;

    private byte extensionsPresent;

    private short extensionsLength;

    private List<HelloExtension> extensions;

    public ClientHello() {
        super(CLIENT_HELLO, 0);

        // This may or may not get set later.
        sessionId = new byte[0];
        cipherSuites = new ArrayList<>();
        extensions = new ArrayList<>();
    }

    public ClientHello(byte[] encoding) {
        super(CLIENT_HELLO, encoding);
    }

    @Override
    protected void decode(byte[] encoding) {

        ByteBuffer encoded = ByteBuffer.wrap(encoding);

        // Version
        byte majorVersion = encoded.get();
        byte minorVersion = encoded.get();
        version = new RecordLayer.ProtocolVersion(majorVersion, minorVersion);

        // Client random
//        gmtUnixTime = encoded.getInt();
        clientRandom = new byte[CLIENT_RANDOM_LENGTH];
        encoded.get(clientRandom);

        // Session ID
        byte sessionIdLength = encoded.get();
        if (sessionIdLength > 0) {
            sessionId = new byte[sessionIdLength];
            encoded.get(sessionId);
        }

        // Cipher suites
        short cipherSuitesLength = encoded.getShort();
        cipherSuites = new ArrayList<>();
        while (cipherSuites.size() < cipherSuitesLength / 2) {
            short cipherSuite = encoded.getShort();
            cipherSuites.add(cipherSuite);
        }

        // Compression method
        compressionMethod = encoded.get();

        // Extensions
        extensions = new ArrayList<>();
        extensionsPresent = encoded.get();
        if (extensionsPresent > 0) {
            short extensionsLength = encoded.getShort();
            int byteCount = 0;
            while (byteCount < extensionsLength) {
                byte extensionType = encoded.get();
                short extensionDataLength = encoded.getShort();
                byte[] extensionData = new byte[extensionDataLength];
                encoded.get(extensionData);
                extensions.add(new HelloExtension(extensionType, extensionData));
                byteCount += extensionDataLength + 3;
            }
        }
    }

    @Override
    public byte[] getEncoded() {
        calculateLengths();
        ByteBuffer encoded = encodeHeader();
        encoded.put(version.majorVersion);
        encoded.put(version.minorVersion);
        encoded.put(clientRandom);
        encoded.putShort((short) sessionId.length);
        encoded.put(sessionId);
        encoded.putShort((short) (cipherSuites.size() * 2));
        for (Short cipherSuite : cipherSuites) {
            encoded.putShort(cipherSuite);
        }
        encoded.put(compressionMethod);
        encoded.put(extensionsPresent);
        encoded.putShort(extensionsLength);
        for (HelloExtension extension : extensions) {
            encoded.put(extension.getEncoded());
        }
        return encoded.array();
    }

    private void calculateLengths() {
        extensionsLength = 0;
        for (HelloExtension extension : extensions) {
            extensionsLength += extension.getExtensionData().length + 1;
        }
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

    public void setCompressionMethod(byte compressionMethod) {
        this.compressionMethod = compressionMethod;
    }

    public void setExtensions(List<HelloExtension> extensions) {
        this.extensions = extensions;
    }
}
