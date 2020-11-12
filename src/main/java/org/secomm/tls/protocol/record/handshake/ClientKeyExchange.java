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
import java.security.InvalidParameterException;

public class ClientKeyExchange implements TlsHandshakeMessage {

    public static final class Builder implements HandshakeMessageFactory.HandshakeBuilder<ClientKeyExchange> {
        public ClientKeyExchange build() {
            return new ClientKeyExchange();
        }
    }

    public ClientKeyExchange() {
    }

    public ClientKeyExchange(byte[] rsaEncryptedSecret) {
        this.rsaEncryptedSecret = rsaEncryptedSecret;
    }

    private byte[] rsaEncryptedSecret;

    @Override
    public byte[] encode() {
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(1024);
        if (CipherSuiteTranslator.getCurrentKeyExchangeAlgorithm() == CipherSuiteTranslator.KeyExchangeAlgorithms.RSA) {
            buffer.putShort((short) rsaEncryptedSecret.length);
            buffer.put(rsaEncryptedSecret);
        } else {
        }
        return buffer.toArray();
    }

    @Override
    public void decode(EncodingByteBuffer handshakeBuffer) throws IOException, InvalidExtensionTypeException {
        if (CipherSuiteTranslator.getCurrentKeyExchangeAlgorithm() == CipherSuiteTranslator.KeyExchangeAlgorithms.RSA) {
            short secretLength = handshakeBuffer.getShort();
            rsaEncryptedSecret = new byte[secretLength];
            handshakeBuffer.get(rsaEncryptedSecret);
        } else {
        }
    }

    @Override
    public byte getHandshakeType() {
        return HandshakeMessageTypes.CLIENT_KEY_EXCHANGE;
    }

}
