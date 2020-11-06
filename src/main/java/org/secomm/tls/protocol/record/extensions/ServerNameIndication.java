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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMEN. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 */

package org.secomm.tls.protocol.record.extensions;

import org.secomm.tls.util.EncodingByteBuffer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Server name indication extension. See RFC 6006, section 3
 *
 * struct {
 *     NameType name_type;
 *     select (name_type) {
 *         case host_name: HostName;
 *     } name;
 * } ServerName;
 *
 * enum {
 *     host_name(0), (255)
 * } NameType;
 *
 * opaque HostName<1..2^16-1>;
 *
 * struct {
 *     ServerName server_name_list<1..2^16-1>
 * } ServerNameList;
 *
 */
public class ServerNameIndication extends AbstractTlsExtension {

    public static class Builder implements ExtensionFactory.ExtensionBuilder {
        @Override
        public ServerNameIndication build() {
            return new ServerNameIndication();
        }
    }

    public static class ServerName {
        public byte nameType;
        public byte[] hostName;
        public ServerName(byte nameType, byte[] hostName) {
            this.nameType = nameType;
            this.hostName = hostName;
        }
    }

    private final List<ServerName> serverNameList;

    public ServerNameIndication(List<String> serverNames) {
        super(Extensions.SERVER_NAME_INDICATION);
        this.serverNameList = new ArrayList<>();
        for (String serverName : serverNames) {
            this.serverNameList.add(new ServerName( (byte)0, serverName.getBytes(StandardCharsets.UTF_8)));
        }
    }

    public ServerNameIndication() {
        super(Extensions.SERVER_NAME_INDICATION);
        this.serverNameList = new ArrayList<>();
    }

    @Override
    protected void encodeExtensionData() {

        EncodingByteBuffer data = EncodingByteBuffer.allocate(1024);
        EncodingByteBuffer nameEncoding = EncodingByteBuffer.allocate(256);
        for (ServerName serverName : serverNameList) {
            nameEncoding.put(serverName.nameType);
            nameEncoding.putShort((short) serverName.hostName.length);
            nameEncoding.put(serverName.hostName);
        }
        byte[] encodedNames = nameEncoding.toArray();
        data.putShort((short) encodedNames.length);
        data.put(encodedNames);
        extensionData = data.toArray();
    }

    @Override
    protected void decodeExtensionData() {

        EncodingByteBuffer data = EncodingByteBuffer.wrap(extensionData);
        short namesLength = data.getShort();
        while (namesLength > 0) {
            byte nameType = data.get();
            namesLength--;
            short nameLength = data.getShort();
            namesLength -= nameLength + 2;
            byte[] nameBytes = new byte[nameLength];
            data.get(nameBytes);
            serverNameList.add(new ServerName(nameType,nameBytes));
        }
    }

    @Override
    public String getText() {
        String text = "Server Name Indication\n";
        for (ServerName serverName : serverNameList) {
            String name = "\tName type: " + serverName.nameType + ", Host name: "
                    + new String(serverName.hostName, StandardCharsets.UTF_8) + "\n";
            text += name;
        }
        return text;
    }
}
