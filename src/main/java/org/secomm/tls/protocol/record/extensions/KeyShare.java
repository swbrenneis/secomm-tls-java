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

import org.secomm.tls.protocol.record.InvalidEncodingException;
import org.secomm.tls.util.EncodingByteBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * RFC 8446 Section 4.2.8
 *
 * struct {
 *     NamedGroup group;
 *     opaque key_exchange<1..2^16-1>;
 * } KeyShareEntry;
 *
 * struct {
 *     KeyShareEntry client_shares<0..2^16-1>;
 * } KeyShareClientHello;
 *
 * struct {
 *     NamedGroup selected_group;
 * } KeyShareHelloRetryRequest;
 *
 * struct {
 *     KeyShareEntry server_share;
 * } KeyShareServerHello;
 *
 */
public class KeyShare extends AbstractTlsExtension {

    public static final class Builder implements ExtensionFactory.ExtensionBuilder<KeyShare> {
        @Override
        public KeyShare build() {
            return new KeyShare();
        }
    }

    public enum KeyShareType { CLIENT_HELLO, HELLO_RETRY, SERVER_HELLO }

    private static final class KeyShareEntry {
        public short group;
        public byte[] keyExchange;
        public KeyShareEntry(short group, byte[] keyExchange) {
            this.group = group;
            this.keyExchange = keyExchange;
        }
    }

    /**
     * Used during ClientHello
     */
    private List<KeyShareEntry> clientShares;

    /**
     * Used during HelloRetry
     */
    private short selectedGroup;

    /**
     * Used during ServerHello
     */
    private KeyShareEntry serverShare;

    /**
     *
     */
    private KeyShareType keyShareType;

    private KeyShare() {
        super(Extensions.KEY_SHARE);
        keyShareType = KeyShareType.CLIENT_HELLO;
    }

    /**
     * ClientHello constructor
     *
     * @param clientShares
     */
    public KeyShare(List<KeyShareEntry> clientShares) {
        super(Extensions.KEY_SHARE);
        this.clientShares = clientShares;
        this.keyShareType = KeyShareType.CLIENT_HELLO;
    }

    /**
     * Server hello constructor
     *
     * @param serverShare
     */
    public KeyShare(KeyShareEntry serverShare) {
        super(Extensions.KEY_SHARE);
        this.serverShare = serverShare;
        this.keyShareType = KeyShareType.SERVER_HELLO;
    }

    /**
     * HelloRetry constructor
     *
     * @param selectedGroup
     */
    public KeyShare(short selectedGroup) {
        super(Extensions.KEY_SHARE);
        this.selectedGroup = selectedGroup;
        this.keyShareType = KeyShareType.HELLO_RETRY;
    }

    @Override
    protected void encodeExtensionData() {
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(1024);
        switch (keyShareType) {
            case CLIENT_HELLO:
                EncodingByteBuffer sharesBuffer = EncodingByteBuffer.allocate(1024);
                for (KeyShareEntry entry : clientShares) {
                    encodeKeyShareEntry(entry, sharesBuffer);
                }
                byte[] sharesBytes = sharesBuffer.toArray();
                buffer.putShort((short) sharesBytes.length);
                buffer.put(sharesBytes);
                break;
            case HELLO_RETRY:
                buffer.putShort(selectedGroup);
                break;
            case SERVER_HELLO:
                EncodingByteBuffer shareBuffer = EncodingByteBuffer.allocate(1024);
                encodeKeyShareEntry(serverShare, shareBuffer);
                byte[] shareBytes = shareBuffer.toArray();
                buffer.putShort((short) shareBytes.length);
                buffer.put(shareBytes);
                break;
        }
        extensionData = buffer.toArray();
    }

    @Override
    protected void decodeExtensionData() {
        EncodingByteBuffer data = EncodingByteBuffer.wrap(extensionData);
        switch (keyShareType) {
            case CLIENT_HELLO:
              short clientSharesLength = data.getShort();
              byte[] clientSharesBytes = new byte[clientSharesLength];
              data.get(clientSharesBytes);
              EncodingByteBuffer sharesBuffer = EncodingByteBuffer.wrap(clientSharesBytes);
              clientShares = new ArrayList<>();
              while (sharesBuffer.hasRemaining()) {
                  clientShares.add(decodeKeyShareEntry(sharesBuffer));
              }
              break;
            case HELLO_RETRY:
                selectedGroup = data.getShort();
                break;
            case SERVER_HELLO:
                serverShare = decodeKeyShareEntry(data);
        }
    }

    @Override
    public String getText() throws InvalidEncodingException {
        return null;
    }

    public void setKeyShareType(KeyShareType keyShareType) {
        this.keyShareType = keyShareType;
    }

    private void encodeKeyShareEntry(KeyShareEntry entry, EncodingByteBuffer buffer) {
        buffer.putShort(entry.group);
        buffer.putShort((short) entry.keyExchange.length);
        buffer.put(entry.keyExchange);
    }

    private KeyShareEntry decodeKeyShareEntry(EncodingByteBuffer data) {
        short group = data.getShort();
        short exchangeLength = data.getShort();
        byte[] keyExchange = new byte[exchangeLength];
        data.get(keyExchange);
        return new KeyShareEntry(group, keyExchange);
    }
}
