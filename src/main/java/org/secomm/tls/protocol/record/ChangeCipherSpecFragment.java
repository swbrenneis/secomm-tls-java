package org.secomm.tls.protocol.record;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public class ChangeCipherSpecFragment implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<ChangeCipherSpecFragment> {
        public ChangeCipherSpecFragment build() throws InvalidEncodingException {
            return new ChangeCipherSpecFragment();
        }
    }

    private byte type;

    public ChangeCipherSpecFragment() {
        type = 1;
    }

    @Override
    public void decode(ByteBuffer buffer) throws InvalidEncodingException, IOException {

        type = buffer.get();
        if (type != 1) {
            throw new InvalidEncodingException("Invalid change cipher spec type");
        }
    }

    @Override
    public void encode(OutputStream out) throws IOException {
        out.write(type);
    }

    @Override
    public short getLength() {
        return 1;
    }
}
