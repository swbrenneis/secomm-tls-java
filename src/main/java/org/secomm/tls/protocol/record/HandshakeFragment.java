package org.secomm.tls.protocol.record;

public class HandshakeFragment implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<HandshakeFragment> {
        public HandshakeFragment build(byte[] encoded) {
            return new HandshakeFragment(encoded);
        }
    }

    public HandshakeFragment(byte[] encoded) {

    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

}
