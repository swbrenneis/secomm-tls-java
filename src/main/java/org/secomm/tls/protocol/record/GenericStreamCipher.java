package org.secomm.tls.protocol.record;

import java.nio.ByteBuffer;

public class GenericStreamCipher implements TlsFragment {

    private final byte[] content;

    private final byte[] mac;

    public GenericStreamCipher(byte[] encoded, int contentLength, int macLength) {

        ByteBuffer encoding = ByteBuffer.wrap(encoded);
        content = new byte[contentLength];
        mac = new byte[macLength];
        encoding.get(content);
        encoding.get(mac);
    }

    @Override
    public byte[] getEncoded() {

        ByteBuffer encoded = ByteBuffer.allocate(content.length + mac.length);
        encoded.put(content);
        encoded.put(mac);
        return encoded.array();
    }
}
