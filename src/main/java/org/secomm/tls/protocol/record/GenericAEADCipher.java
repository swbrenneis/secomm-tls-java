package org.secomm.tls.protocol.record;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public class GenericAEADCipher implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<GenericAEADCipher> {
        @Override
        public GenericAEADCipher build() throws InvalidEncodingException, InvalidHandshakeType {
            return new GenericAEADCipher();
        }
    }

    private byte[] nonceExplicit;

    private byte[] content;

    @Override
    public void encode(OutputStream out) throws IOException {

        NumberReaderWriter.writeShort((short) nonceExplicit.length, out);
        out.write(nonceExplicit);
        NumberReaderWriter.writeShort((short) content.length, out);
        out.write(content);
    }

    @Override
    public short getLength() {
        return (short) (2 + nonceExplicit.length + 2 + content.length);
    }

    @Override
    public void decode(ByteBuffer buffer) throws IOException, InvalidHandshakeType, InvalidEncodingException {

    }
}
