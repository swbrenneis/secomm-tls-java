package org.secomm.tls.protocol.record;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.net.PortUnreachableException;
import java.nio.ByteBuffer;

public class GenericStreamCipher implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<GenericStreamCipher> {
        @Override
        public GenericStreamCipher build() throws InvalidEncodingException, InvalidHandshakeType {
            return new GenericStreamCipher();
        }
    }

    private byte[] content;

    private byte[] mac;

    public GenericStreamCipher() {

    }

    @Override
    public void decode(ByteBuffer buffer) throws IOException {

        short contentLength = NumberReaderWriter.readShort(buffer);
        content = new byte[contentLength];
        buffer.get(content);
        short macLength = NumberReaderWriter.readShort(buffer);
        mac = new byte[macLength];
        buffer.get(mac);
    }

    @Override
    public void encode(OutputStream out) throws IOException {

        NumberReaderWriter.writeShort((short) content.length, out);
        out.write(content);
        NumberReaderWriter.writeShort((short) mac.length, out);
        out.write(mac);
    }

    @Override
    public short getLength() {
        return (short) (2 + content.length + 2 + mac.length);
    }

}
