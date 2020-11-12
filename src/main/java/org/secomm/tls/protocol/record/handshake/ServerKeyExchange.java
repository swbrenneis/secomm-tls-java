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
import org.secomm.tls.protocol.SignatureAndHashAlgorithm;
import org.secomm.tls.util.EncodingByteBuffer;

public class ServerKeyExchange implements TlsHandshakeMessage {

    public static final class Builder implements HandshakeMessageFactory.HandshakeBuilder<ServerKeyExchange> {
        public ServerKeyExchange build() {
            return new ServerKeyExchange();
        }
    }

    public static final class ServerDHParameters {
        public byte[] dh_p;
        public byte[] dh_g;
        public byte[] dh_Ys;
        public ServerDHParameters(byte[] dh_p, byte[] dh_g, byte[] dh_Ys) {
            this.dh_p = dh_p;
            this.dh_g = dh_g;
            this.dh_Ys = dh_Ys;
        }
    }

    private ServerDHParameters serverDHParameters;

    private SignatureAndHashAlgorithm signatureAndHashAlgorithm;

    private byte[] signature;

    @Override
    public byte[] encode() {
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(2048);
        switch(CipherSuiteTranslator.getCurrentKeyExchangeAlgorithm()) {
            case DH_ANON:
                encodeDHParameters(buffer);
                break;
            case DHE_DSS:
            case DHE_RSA:
                encodeDHParameters(buffer);
                buffer.putShort(signatureAndHashAlgorithm.getAlgorithm());
                buffer.putShort((short) signature.length);
                buffer.put(signature);
            case DH_DSS:
            case DH_RSA:
                break;
        }
        return buffer.toArray();
    }

    @Override
    public void decode(EncodingByteBuffer handshakeBuffer) {

        switch (CipherSuiteTranslator.getCurrentKeyExchangeAlgorithm()) {
            case DH_ANON:
                decodeDHParameters(handshakeBuffer);
                break;
            case DHE_DSS:
            case DHE_RSA:
                decodeDHParameters(handshakeBuffer);
                short algorithm = handshakeBuffer.getShort();
                signatureAndHashAlgorithm = new SignatureAndHashAlgorithm(algorithm);
                short sigLength = handshakeBuffer.getShort();
                signature = new byte[sigLength];
                handshakeBuffer.get(signature);
            case RSA:
            case DH_DSS:
            case DH_RSA:
                break;
        }
    }

    private void decodeDHParameters(EncodingByteBuffer buffer) {
        short paramLength = buffer.getShort();
        byte[] dh_p = new byte[paramLength];
        buffer.get(dh_p);
        paramLength = buffer.getShort();
        byte[] dh_g = new byte[paramLength];
        buffer.get(dh_g);
        paramLength = buffer.getShort();
        byte[] dh_Ys = new byte[paramLength];
        buffer.get(dh_Ys);
        serverDHParameters = new ServerDHParameters(dh_p, dh_g, dh_Ys);
    }

    void encodeDHParameters(EncodingByteBuffer buffer) {
        buffer.putShort((short) serverDHParameters.dh_p.length);
        buffer.put(serverDHParameters.dh_p);
        buffer.putShort((short) serverDHParameters.dh_g.length);
        buffer.put(serverDHParameters.dh_g);
        buffer.putShort((short) serverDHParameters.dh_Ys.length);
        buffer.put(serverDHParameters.dh_Ys);
    }

    @Override
    public byte getHandshakeType() {
        return HandshakeMessageTypes.SERVER_KEY_EXCHANGE;
    }

    public ServerDHParameters getServerDHParameters() {
        return serverDHParameters;
    }

    public byte[] getSignature() {
        return signature;
    }

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
        return signatureAndHashAlgorithm;
    }
}
