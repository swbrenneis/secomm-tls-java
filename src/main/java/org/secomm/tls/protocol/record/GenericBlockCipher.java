package org.secomm.tls.protocol.record;

import java.nio.ByteBuffer;

public class GenericBlockCipher implements TlsFragment {

    private byte[] iv;

    private byte[] content;

    private byte[] mac;

    private byte[] padding;

    private byte paddingLength;

    @Override
    public byte[] getEncoded() {

        ByteBuffer encoded = ByteBuffer.allocate(iv.length + content.length + mac.length + padding.length + 1);
        encoded.put(iv);
        encoded.put(content);
        encoded.put(mac);
        encoded.put(padding);
        encoded.put(paddingLength);

        return encoded.array();
    }
}
