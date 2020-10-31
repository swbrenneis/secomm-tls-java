package org.secomm.tls.protocol.record;

import java.nio.ByteBuffer;

public class GenericAEADCipher implements TlsFragment {

    private byte[] nonceExplicit;

    private byte[] content;

    @Override
    public byte[] getEncoded() {

        ByteBuffer encoding = ByteBuffer.allocate(nonceExplicit.length + content.length);
        encoding.put(nonceExplicit);
        encoding.put(content);

        return encoding.array();
    }
}
