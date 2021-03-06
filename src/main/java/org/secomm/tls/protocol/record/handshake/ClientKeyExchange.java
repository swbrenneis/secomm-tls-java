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

package org.secomm.tls.protocol.record.handshake;

import org.secomm.tls.crypto.CipherSuiteTranslator;
import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;
import org.secomm.tls.util.EncodingByteBuffer;

import java.io.IOException;

public class ClientKeyExchange implements TlsHandshakeMessage {

    public static final class Builder implements HandshakeMessageFactory.HandshakeBuilder<ClientKeyExchange> {
        public ClientKeyExchange build() {
            return new ClientKeyExchange();
        }
    }

    public ClientKeyExchange() {
    }

    private byte[] premasterSecret;

    private byte[] clientPublicKey;

    @Override
    public byte[] encode() {
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(1024);
        if (CipherSuiteTranslator.getKeyExchangeAlgorithm() == CipherSuiteTranslator.KeyExchangeAlgorithm.RSA) {
            buffer.putShort((short) premasterSecret.length);
            buffer.put(premasterSecret);
        } else {
            buffer.putShort((short) clientPublicKey.length);
            buffer.put(clientPublicKey);
        }
        return buffer.toArray();
    }

    @Override
    public void decode(EncodingByteBuffer handshakeBuffer) throws IOException, InvalidExtensionTypeException {
        if (CipherSuiteTranslator.getKeyExchangeAlgorithm() == CipherSuiteTranslator.KeyExchangeAlgorithm.RSA) {
            short secretLength = handshakeBuffer.getShort();
            premasterSecret = new byte[secretLength];
            handshakeBuffer.get(premasterSecret);
        } else {
            short keyLength = handshakeBuffer.getShort();
            clientPublicKey = new byte[keyLength];
            handshakeBuffer.get(clientPublicKey);
        }
    }

    @Override
    public byte getHandshakeMessageType() {
        return HandshakeMessageTypes.CLIENT_KEY_EXCHANGE;
    }

    public void setPremasterSecret(byte[] premasterSecret) {
        this.premasterSecret = premasterSecret;
    }

    public void setClientPublicKey(byte[] clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }
}
