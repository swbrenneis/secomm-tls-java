package org.secomm.tls.protocol.record;

import org.secomm.tls.protocol.record.extensions.HelloExtension;

import java.nio.ByteBuffer;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;

public class ClientHello extends Handshake {

    private RecordLayer.ProtocolVersion version;

    private int gmtUnixTime;

    private byte clientRandomLength;

    private byte[] clientRandom;

    private short sessionIdLength;

    private byte[] sessionId;

    private short cipherSuitesLength;

    private List<byte[]> cipherSuites;

    private byte compressionMethod;

    private byte extensionsPresent;

    private short extensionsLength;

    private List<HelloExtension> extensions;

    public ClientHello() {
        super(CLIENT_HELLO, 0);

        // This may or may not get set later.
        sessionId = new byte[0];
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
        gmtUnixTime = encoded.getInt();
        byte clientRandomLength = encoded.get();
        clientRandom = new byte[clientRandomLength];
        encoded.get(clientRandom);

        // Session ID
        short sessionIdLength = encoded.getShort();
        if (sessionIdLength > 0) {
            sessionId = new byte[sessionIdLength];
            encoded.get(sessionId);
        }

        // Cipher suites
        short cipherSuitesLength = encoded.getShort();
        cipherSuites = new ArrayList<>();
        while (cipherSuites.size() < cipherSuitesLength / 2) {
            byte[] cipherSuite = new byte[2];
            encoded.get(cipherSuite);
            cipherSuites.add(cipherSuite);
        }

        // Compression method
        compressionMethod = encoded.get();

        // Extensions
        extensions = new ArrayList<>();
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

    @Override
    public byte[] getEncoded() {
        calculateLengths();
        ByteBuffer encoded = encodeHeader();
        encoded.put(version.majorVersion);
        encoded.put(version.minorVersion);
        encoded.putInt(gmtUnixTime);
        encoded.put(clientRandomLength);
        encoded.put(clientRandom);
        encoded.putShort(sessionIdLength);
        encoded.put(sessionId);
        encoded.putShort(cipherSuitesLength);
        encoded.putShort((short) (cipherSuites.size() * 2));
        for (byte[] cipherSuite : cipherSuites) {
            encoded.put(cipherSuite);
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
        length = 2;                     // version
        length += 4;                    // gmtUnixTime
        length += 1;                    // clientRandomLength
        clientRandomLength = (byte) clientRandom.length;
        length += clientRandomLength;
        length += 1;                    // sessionId length
        sessionIdLength = (short) sessionId.length;
        length += sessionIdLength;
        length += 2;                    // cipherSuites length
        length += cipherSuitesLength;
        length += 2;                    // compressionMethod and extensions present
        length += 2;                    // extensionsLength
        for (HelloExtension extension : extensions) {
            cipherSuitesLength += extension.getEncoded().length;
        }
        length += cipherSuitesLength;
    }

    public void setRandom(int gmtUnixTime, byte[] clientRandom) {
        if (clientRandom.length != 28) {
            throw new InvalidParameterException("Invalid client random size");
        }
        this.gmtUnixTime = gmtUnixTime;
        this.clientRandom = clientRandom;
    }

    public void setGmtUnixTime(int gmtUnixTime) {
        this.gmtUnixTime = gmtUnixTime;
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    public void setCipherSuites(List<byte[]> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public void setCompressionMethod(byte compressionMethod) {
        this.compressionMethod = compressionMethod;
    }

    public void setExtensions(List<HelloExtension> extensions) {
        this.extensions = extensions;
    }
}
