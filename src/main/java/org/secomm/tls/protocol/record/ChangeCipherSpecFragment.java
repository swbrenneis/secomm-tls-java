package org.secomm.tls.protocol.record;

public class ChangeCipherSpecFragment implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<ChangeCipherSpecFragment> {
        public ChangeCipherSpecFragment build(byte[] encoded) throws InvalidEncodingException {
            return new ChangeCipherSpecFragment(encoded);
        }
    }

    private final byte type;

    public ChangeCipherSpecFragment() {
        type = 1;
    }

    public ChangeCipherSpecFragment(byte[] encoded) throws InvalidEncodingException {
        type = encoded[0];
        if (encoded.length != 1 || type != 1) {
            throw new InvalidEncodingException("Invalid change cipher spec type");
        }
    }

    @Override
    public byte[] getEncoded() {
        byte[] encoded = new byte[1];
        encoded[0] = type;
        return encoded;
    }
}
