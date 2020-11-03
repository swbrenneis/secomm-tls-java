package org.secomm.tls.protocol.record;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public interface Handshake {

    public void encode(OutputStream out) throws IOException;

    public short getLength();

    public void decode(ByteBuffer handshakeBuffer) throws IOException;
}
