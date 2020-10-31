package org.secomm.tls.protocol.record;

public class HelloRequest extends Handshake {

    public HelloRequest() {
        super(HELLO_REQUEST, 0);
    }

    @Override
    public byte[] getEncoded() {
        return encodeHeader().array();
    }
}
