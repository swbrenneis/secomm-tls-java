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

import org.secomm.tls.crypto.Algorithms;
import org.secomm.tls.protocol.CipherSuites;
import org.secomm.tls.protocol.SecurityParameters;
import org.secomm.tls.protocol.record.extensions.ExtensionFactory;
import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.net.Socket;
import java.security.SecureRandom;

/**
 * The record layer manages handshaking and keeps track of
 * the current and pending cipher specs. There is one record layer
 * instance per session.
 */
public class RecordLayer {

    public static final class ProtocolVersion {
        public byte majorVersion;
        public byte minorVersion;
        public ProtocolVersion(byte majorVersion, byte minorVersion) {
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
        }
    }

    public static final ProtocolVersion TLS_1_0 = new ProtocolVersion((byte) 0x03, (byte) 0x01);
    public static final ProtocolVersion TLS_1_2 = new ProtocolVersion((byte) 0x03, (byte) 0x03);

    private final ProtocolVersion version;

    private final SecureRandom secureRandom;

    private SecurityParameters pendingCipherSpec;

    private SecurityParameters currentCipherSpec;

    private byte[] sessionId;

    private Socket clientSocket;

    public RecordLayer(ProtocolVersion version, SecureRandom secureRandom) {
        this.version = version;
        this.secureRandom = secureRandom;
    }

    public void connect(String address, int port) throws IOException {

        clientSocket = new Socket(address, port);
    }

    public byte[] getClientHello() throws IOException {

        TlsPlaintextRecord record = new TlsPlaintextRecord(TlsRecord.HANDSHAKE, version);

        ClientHello clientHello = new ClientHello();
        byte[] randomBytes = new byte[ClientHello.CLIENT_RANDOM_LENGTH];
        secureRandom.nextBytes(randomBytes);
        clientHello.setClientRandom(randomBytes);
        if (sessionId != null) {
            clientHello.setSessionId(sessionId);
        }
        clientHello.setCipherSuites(CipherSuites.defaultCipherSuites);
        clientHello.setExtensions(ExtensionFactory.getCurrentExtensions());

        HandshakeFragment handshakeFragment = new HandshakeFragment(HandshakeTypes.CLIENT_HELLO, clientHello);
        record.setFragment(handshakeFragment);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        return record.encode();
    }

    public TlsPlaintextRecord readPlaintextRecord(InputStream in)
            throws InvalidEncodingException, InvalidContentTypeException, InvalidHandshakeType, IOException,
            InvalidExtensionTypeException {

        TlsPlaintextRecord record = new TlsPlaintextRecord();
        record.decode(in);
        return record;
    }

    private void initializeSecurityParameters() {
        pendingCipherSpec = new SecurityParameters(SecurityParameters.ConnectionEnd.CLIENT);
        pendingCipherSpec.setPrfAlgorithm(Algorithms.getPrfAlgorithm(Algorithms.PrfAlgorithms.TLS_PRF_SHA256));
    }
}
