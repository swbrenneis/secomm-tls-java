package org.secomm.tls.protocol.record;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public class HelloRequest extends AbstractHandshake {

    public static final class Builder implements HandshakeContentFactory.HandshakeBuilder<HelloRequest> {

        @Override
        public HelloRequest build() {
            return new HelloRequest();
        }
    }

    public HelloRequest() {
        super(HandshakeTypes.HELLO_REQUEST);
    }

    @Override
    public void decode(ByteBuffer buffer) throws IOException {
    }

    @Override
    protected void calculateHandshakeLength() {
        length = 3;
    }

    @Override
    public void encode(OutputStream out) throws IOException {
        encodeHeader(out);
    }
}
