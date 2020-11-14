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

import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;
import org.secomm.tls.util.EncodingByteBuffer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class ServerCertificate implements TlsHandshakeMessage {

    public static final class Builder implements HandshakeMessageFactory.HandshakeBuilder<ServerCertificate> {
        public ServerCertificate build() { return new ServerCertificate(); }
    }

    private final List<byte[]> certificateChain;

    private int chainLength;

    public ServerCertificate() {
        this.certificateChain = new ArrayList<>();
    }

    @Override
    public byte[] encode() {
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(chainLength + 3);
        buffer.put24Bit(chainLength);
        for (byte[] certBytes : certificateChain) {
            buffer.put24Bit(certBytes.length);
            buffer.put(certBytes);
        }
        return buffer.toArray();
    }

    @Override
    public void decode(EncodingByteBuffer handshakeBuffer) throws IOException, InvalidExtensionTypeException {
        int tempLength = handshakeBuffer.get24Bit();
        while (tempLength > 0) {
            int certLength = handshakeBuffer.get24Bit();
            tempLength -= 3;
            byte[] certBytes = new byte[certLength];
            handshakeBuffer.get(certBytes);
            certificateChain.add(certBytes);
            tempLength -= certLength;
        }
    }

    @Override
    public byte getHandshakeMessageType() {
        return HandshakeMessageTypes.CERTIFICATE;
    }

    /**
     * Decode and return the certificate at the given index. May throw index out of
     * bounds exception.
     *
     * @param index
     * @return
     * @throws CertificateException
     */
    public X509Certificate getCertificate(int index) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream in = new ByteArrayInputStream(certificateChain.get(index));
        return (X509Certificate) factory.generateCertificate(in);
    }
}
