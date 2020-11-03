package org.secomm.tls.protocol.record.extensions;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public abstract class AbstractExtension implements Extension {

    protected final short extensionType;

    protected byte[] extensionData;

    protected AbstractExtension(short extensionType) {
        this.extensionType = extensionType;
    }

    @Override
    public void encode(OutputStream out) throws IOException {
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        encodeExtensionData();
        NumberReaderWriter.writeShort(extensionType, out);
        NumberReaderWriter.writeShort((short) extensionData.length, out);
        out.write(extensionData);
    }

    protected abstract void encodeExtensionData() throws IOException;

}
