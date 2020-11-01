package org.secomm.tls.protocol.record;

import java.nio.ByteBuffer;

public class HandshakeFragmentImpl implements HandshakeFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<HandshakeFragmentImpl> {
        public HandshakeFragmentImpl build(byte[] encoded) throws InvalidHandshakeType {
            return new HandshakeFragmentImpl(encoded);
        }
    }

    private byte handshakeType;

    private AbstractHandshake handshake;

    public HandshakeFragmentImpl(byte handshakeType, AbstractHandshake handshake) {
        this.handshakeType = handshakeType;
        this.handshake = handshake;
    }

    public HandshakeFragmentImpl(byte[] encoding) throws InvalidHandshakeType {
        ByteBuffer encoded = ByteBuffer.wrap(encoding);
        handshakeType = encoded.get();
        byte[] lengthBytes = new byte[3];
        encoded.get(lengthBytes);
        int handshakeLength = (lengthBytes[0] & 0xff);
        handshakeLength = handshakeLength << 8;
        handshakeLength |= (lengthBytes[1] & 0xff);
        handshakeLength = handshakeLength << 8;
        handshakeLength |= (lengthBytes[2] & 0xff);
        byte[] handshakeBytes = new byte[handshakeLength];
        encoded.get(handshakeBytes);
        handshake = HandshakeContentFactory.getHandshake(handshakeType, handshakeBytes);
    }

    @Override
    public byte[] getEncoded() {
        byte[] encoding = handshake.getEncoded();
        ByteBuffer encoded = ByteBuffer.allocate(encoding.length + 3);
        encoded.put(handshakeType);
        encoded.putShort((short) encoding.length);
        encoded.put(encoding);
        return encoded.array();
    }

    @Override
    public AbstractHandshake getHandshake() {
        return handshake;
    }
}
