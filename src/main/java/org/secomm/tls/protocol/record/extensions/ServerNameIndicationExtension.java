package org.secomm.tls.protocol.record.extensions;

import org.secomm.tls.util.NumberReaderWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ServerNameIndicationExtension extends AbstractExtension {

    private List<String> hostNames;

    public ServerNameIndicationExtension(List<String> hostNames) {
        super(Extensions.SERVER_NAME_INDICATION);
        this.hostNames = hostNames;
    }

    public ServerNameIndicationExtension() {
        super(Extensions.SERVER_NAME_INDICATION);

        this.hostNames = new ArrayList<>();
    }

    @Override
    protected void encodeExtensionData() throws IOException {

        short hostNameLength = 0;
        for (String hostName : hostNames) {
            hostNameLength += hostName.length() + 3;    // Host name type + host name length + host name
        }
        // Encode the host names
        ByteBuffer data = ByteBuffer.allocate(hostNameLength);
        for (String hostName : hostNames) {
            data.put((byte) 0);    // Host name type
            data.putShort((short) hostName.length());
            data.put(hostName.getBytes(StandardCharsets.UTF_8));
        }
        extensionData = data.array();
    }
}
