package org.secomm.tls.protocol.record.extensions;

import java.nio.ByteBuffer;

public class HelloExtension {

    public static final byte SIGNATURE_ALGORITHMS = 13;

    private byte extensionType;

    private byte[] extensionData;

    public HelloExtension(byte extensionType, byte[] extensionData) {
        this.extensionType = extensionType;
        this.extensionData = extensionData;
    }

    public byte[] getEncoded() {
        ByteBuffer encoded = ByteBuffer.allocate(extensionData.length + 1);
        encoded.put(extensionType);
        encoded.putShort((short) extensionData.length);
        encoded.put(extensionData);
        return encoded.array();
    }

    public byte getExtensionType() {
        return extensionType;
    }

    public void setExtensionType(byte extensionType) {
        this.extensionType = extensionType;
    }

    public byte[] getExtensionData() {
        return extensionData;
    }

    public void setExtensionData(byte[] extensionData) {
        this.extensionData = extensionData;
    }
}
