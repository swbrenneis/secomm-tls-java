package org.secomm.tls.protocol.record;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public class TlsPlaintextRecord extends TlsRecord {

    public TlsPlaintextRecord(byte contentType, RecordLayer.ProtocolVersion version) {
        super(contentType, version);
    }

    public TlsPlaintextRecord() {
    }

    public void decode(Reader in)
            throws InvalidContentType, InvalidEncodingException, InvalidHandshakeType, IOException {

        byte[] headerBytes = new byte[5];
        NumberReaderWriter.readBytes(headerBytes, in);
        ByteBuffer headerBuffer = ByteBuffer.wrap(headerBytes);
        contentType = headerBuffer.get();
        version = new RecordLayer.ProtocolVersion(headerBuffer.get(), headerBuffer.get());
        short length = headerBuffer.getShort();
        fragment = ContentFactory.getContent(contentType);
        byte[] fragmentBytes = new byte[length];
        NumberReaderWriter.readBytes(fragmentBytes, in);
        ByteBuffer fragmentBuffer = ByteBuffer.wrap(fragmentBytes);
        fragment.decode(fragmentBuffer);
    }

    public void encode(OutputStream out) throws IOException {

        out.write(contentType);
        out.write(version.majorVersion);
        out.write(version.minorVersion);
        NumberReaderWriter.writeShort(fragment.getLength(), out);
        fragment.encode(out);
    }

}
