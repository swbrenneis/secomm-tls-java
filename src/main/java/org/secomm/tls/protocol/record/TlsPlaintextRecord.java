package org.secomm.tls.protocol.record;

import java.nio.ByteBuffer;

public class TlsPlaintextRecord extends TlsRecord {

    public TlsPlaintextRecord(byte contentType, RecordLayer.ProtocolVersion version) {
        super(contentType, version);
    }

    public TlsPlaintextRecord(byte[] encoded) throws InvalidContentType, InvalidEncodingException, InvalidHandshakeType {

        ByteBuffer encoding = ByteBuffer.wrap(encoded);
        contentType = encoding.get();
        byte majorVersion = encoding.get();
        byte minorVersion = encoding.get();
        version = new RecordLayer.ProtocolVersion(majorVersion, minorVersion);
        short length = encoding.getShort();
        byte[] fragmentEncoding = new byte[length];
        encoding.get(fragmentEncoding);
        fragment = ContentFactory.getContent(contentType, fragmentEncoding);
    }

    public byte[] getEncoded() {

        byte[] encoding = fragment.getEncoded();
        ByteBuffer encoded = ByteBuffer.allocate(encoding.length + 5);
        encoded.put(contentType);
        encoded.put(version.majorVersion);
        encoded.put(version.minorVersion);
        encoded.putShort((short) encoding.length);
        encoded.put(encoding);

        return encoded.array();
    }

    public void setContent(byte[] content) throws InvalidContentType, InvalidEncodingException, InvalidHandshakeType {
        fragment = ContentFactory.getContent(contentType, content);
    }

}
