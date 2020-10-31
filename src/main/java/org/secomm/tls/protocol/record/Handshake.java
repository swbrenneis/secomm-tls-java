package org.secomm.tls.protocol.record;

import java.nio.ByteBuffer;

public abstract class Handshake {

    // Handshake types
    public static final byte HELLO_REQUEST = 0;
    public static final byte CLIENT_HELLO = 1;
    public static final byte SERVER_HELLO = 2;
    public static final byte CERTIFICATE = 11;
    public static final byte SERVER_KEY_EXCHANGE  = 12;
    public static final byte CERTIFICATE_REQUEST = 13;
    public static final byte SERVER_HELLO_DONE = 14;
    public static final byte CERTIFICATE_VERIFY = 15;
    public static final byte CLIENT_KEY_EXCHANGE = 16;
    public static final byte FINISHED = 20;

    protected byte handshakeType;

    /**
     * The handshake message length. This is transmitted
     * as a 24 bit number.
     */
    protected int length;

    protected Handshake(byte handshakeType, int length) {
        this.handshakeType = handshakeType;
        this.length = length;
    }

    public abstract byte[] getEncoded();

    protected ByteBuffer encodeHeader() {

        ByteBuffer encoded = ByteBuffer.allocate(length + 4);
        encoded.put(handshakeType);
        int temp = length;
        byte[] length24 = new byte[3];
        length24[2] = (byte) (temp & 0xff);
        temp = temp >> 8;
        length24[1] = (byte) (temp & 0xff);
        temp = temp >> 8;
        length24[0] = (byte) (temp & 0xff);
        encoded.put(length24);
        return encoded;
    }

}
