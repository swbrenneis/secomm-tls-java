package org.secomm.tls.protocol.record;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class HandshakeFragment implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<HandshakeFragment> {
        public HandshakeFragment build() throws InvalidHandshakeType {
            return new HandshakeFragment();
        }
    }

    private byte handshakeType;

    private Handshake handshake;

    public HandshakeFragment(byte handshakeType, AbstractHandshake handshake) {
        this.handshakeType = handshakeType;
        this.handshake = handshake;
    }

    public HandshakeFragment() {
    }

    @Override
    public void decode(ByteBuffer handshakeBuffer) throws InvalidHandshakeType, IOException {
        
        handshakeType = handshakeBuffer.get();
//        int handshakeLength = NumberReaderWriter.read24Bit(handshakeBuffer);
        handshake = HandshakeContentFactory.getHandshake(handshakeType);
        int wrong = NumberReaderWriter.read24Bit(handshakeBuffer);
        // Firefox sends the wrong handshake length. It should be the total
        // record size - 4. Handshake type + 24 bit length. It sends total
        // record size - 3.
        int handshakeLength = handshakeBuffer.array().length - 4;
        byte[] bytes = new byte[handshakeLength];
        handshakeBuffer.get(bytes);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        handshake.decode(buffer);
    }

    @Override
    public void encode(OutputStream out) throws IOException {
        out.write(handshakeType);
        NumberReaderWriter.write24Bit(handshake.getLength(), out);
        handshake.encode(out);
    }

    @Override
    public short getLength() {
        return (short) (handshake.getLength() + 4);
    }

    public Handshake getHandshake() {
        return handshake;
    }
}
