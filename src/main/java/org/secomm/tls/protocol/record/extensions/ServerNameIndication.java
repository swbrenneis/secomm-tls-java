/*
 * Copyright (c) 2020 Steve Brenneis.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following
 * conditions: The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
 * EXPRESSOR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMEN.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 */

package org.secomm.tls.protocol.record.extensions;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ServerNameIndication extends AbstractExtension {

    public static class Builder implements ExtensionFactory.ExtensionBuilder {
        @Override
        public ServerNameIndication build() {
            return new ServerNameIndication();
        }
    }

    private byte hostNameType;

    private String hostName;

    public ServerNameIndication(String hostName) {
        super(Extensions.SERVER_NAME_INDICATION);
        this.hostName = hostName;
        hostNameType = 0;
    }

    public ServerNameIndication() {
        super(Extensions.SERVER_NAME_INDICATION);
    }

    @Override
    protected void encodeExtensionData() throws IOException {

        ByteBuffer data = ByteBuffer.allocate(hostName.length() + 3);
        data.put(hostNameType);
        data.putShort((short) hostName.length());
        data.put(hostName.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void decodeExtensionData() {

        ByteBuffer data = ByteBuffer.wrap(extensionData);
        hostNameType = data.get(); // Always 0, not used for anything.
        short length = data.getShort();
        byte[] nameBytes = new byte[length];
        hostName = new String(nameBytes, StandardCharsets.UTF_8);
    }

    @Override
    public String getText() {
        String text = "Server Name Indication\n";
        text += "\tHost name type " + hostNameType + "\n";
        text += "\tHost name " + hostName + "\n";
        return text;
    }
}
