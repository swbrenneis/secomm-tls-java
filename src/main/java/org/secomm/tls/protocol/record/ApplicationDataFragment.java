package org.secomm.tls.protocol.record;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public class ApplicationDataFragment implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<ApplicationDataFragment> {
        public ApplicationDataFragment build() {
            return new ApplicationDataFragment();
        }
    }

    public ApplicationDataFragment() {
        
    }

    @Override
    public void encode(OutputStream out) throws IOException {

    }

    @Override
    public short getLength() {
        return 0;
    }

    @Override
    public void decode(ByteBuffer buffer) throws IOException, InvalidHandshakeType, InvalidEncodingException {

    }
}
