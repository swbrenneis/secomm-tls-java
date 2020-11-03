package org.secomm.tls.protocol.record;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public abstract class AbstractHandshake implements Handshake {

    protected byte handshakeType;

    /**
     * The handshake message length. This is transmitted
     * as a 24 bit number.
     */
    protected int length;

/*
    protected AbstractHandshake(byte handshakeType, int length) {
        this.handshakeType = handshakeType;
        this.length = length;
    }
*/

    protected AbstractHandshake(byte handshakeType) {
        this.handshakeType = handshakeType;
    }

    protected abstract void calculateHandshakeLength();

    protected void encodeHeader(OutputStream out) throws IOException {

        out.write(handshakeType);
        if (length == 0) {
            calculateHandshakeLength();
        }
        NumberReaderWriter.write24Bit(length, out);
    }

    @Override
    public short getLength() {
        if (length == 0) {
            calculateHandshakeLength();
        }
        return (short) length;
    }
}
