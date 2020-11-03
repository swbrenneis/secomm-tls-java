package org.secomm.tls.protocol.record;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public class GenericBlockCipher implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<GenericBlockCipher> {
        @Override
        public GenericBlockCipher build() throws InvalidEncodingException, InvalidHandshakeType {
            return new GenericBlockCipher();
        }
    }

    private byte[] iv;

    private byte[] content;

    private byte[] mac;

    private byte[] padding;

    private byte paddingLength;

    @Override
    public void encode(OutputStream out) throws IOException {

        NumberReaderWriter.writeShort((short) iv.length, out);
        out.write(iv);
        NumberReaderWriter.writeShort((short) content.length, out);
        out.write(content);
        NumberReaderWriter.writeShort((short) mac.length, out);
        out.write(mac);
        out.write(padding);
        out.write(paddingLength);
    }

    @Override
    public short getLength() {
        return (short) (2 + iv.length + 2 + content.length + 2 + mac.length + padding.length + 1);
    }

    @Override
    public void decode(ByteBuffer buffer) throws IOException, InvalidHandshakeType, InvalidEncodingException {

        // Hmmm
    }
}
