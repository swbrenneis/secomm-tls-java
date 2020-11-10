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

package org.secomm.tls.protocol.record;

import org.secomm.tls.util.EncodingByteBuffer;

public class ServerKeyExchange implements TlsHandshakeMessage {

    public static final class Builder implements HandshakeMessageFactory.HandshakeBuilder<ServerKeyExchange> {
        public ServerKeyExchange build() {
            return new ServerKeyExchange();
        }
    }

    private static final class ServerDHParameters {
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

    private short signatureHashAlgorithm;

    private byte[] paramSignatureHash;

    @Override
    public byte[] encode() {
        if (serverDHParameters != null) {
            EncodingByteBuffer buffer = EncodingByteBuffer.allocate(4096);
            buffer.putShort((short) serverDHParameters.dh_p.length);
            buffer.put(serverDHParameters.dh_p);
            buffer.putShort((short) serverDHParameters.dh_g.length);
            buffer.put(serverDHParameters.dh_g);
            buffer.putShort((short) serverDHParameters.dh_Ys.length);
            buffer.put(serverDHParameters.dh_Ys);
            if (paramSignatureHash != null) {
                buffer.putShort((short) signatureHashAlgorithm);
                buffer.put(paramSignatureHash);
            }
            return buffer.toArray();
        } else {
            return new byte[0];
        }
    }

    @Override
    public void decode(EncodingByteBuffer handshakeBuffer) {

        // If the handshake buffer is empty, it means that the key
        // exchange algorithm is one of RSA, DH DSS, or DH RSA
        // See RFC 5246 Section 7.4.3
        if (handshakeBuffer.hasRemaining()) {
            short paramLength = handshakeBuffer.getShort();
            byte[] dh_p = new byte[paramLength];
            handshakeBuffer.get(dh_p);
            paramLength = handshakeBuffer.getShort();
            byte[] dh_g = new byte[paramLength];
            handshakeBuffer.get(dh_g);
            paramLength = handshakeBuffer.getShort();
            byte[] dh_Ys = new byte[paramLength];
            handshakeBuffer.get(dh_Ys);
            serverDHParameters = new ServerDHParameters(dh_p, dh_g, dh_Ys);
            if (handshakeBuffer.hasRemaining()) {
                signatureHashAlgorithm = handshakeBuffer.getShort();
                paramSignatureHash = new byte[256];         // Constant for all DH and DHE hashes
                handshakeBuffer.get(paramSignatureHash);
            }
        }
    }

    @Override
    public byte getHandshakeType() {
        return HandshakeMessageTypes.SERVER_KEY_EXCHANGE;
    }
}
