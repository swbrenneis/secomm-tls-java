package org.secomm.tls.protocol.record;

public class HelloRequest extends AbstractHandshake {

    public HelloRequest() {
        super(HELLO_REQUEST, 0);
    }

    @Override
    protected void decode(byte[] encoding) {

    }

    @Override
    public byte[] getEncoded() {
        return encodeHeader().array();
    }
}
