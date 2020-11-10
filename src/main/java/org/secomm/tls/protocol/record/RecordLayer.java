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

import org.secomm.tls.net.ConnectionManager;
import org.secomm.tls.protocol.CipherSuites;
import org.secomm.tls.protocol.ConnectionState;
import org.secomm.tls.protocol.SecurityParameters;
import org.secomm.tls.protocol.record.extensions.Extensions;
import org.secomm.tls.protocol.record.extensions.TlsExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

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

    public static final int RECORD_HEADER_LENGTH = 5;

    private final ProtocolVersion version;

    private ConnectionState connectionState;

    private SecurityParameters pendingCipherSpec;

    private SecurityParameters currentCipherSpec;

    private byte[] sessionId;

    private List<Short> currentCipherSuites;

    private List<TlsExtension> currentTlsExtensions;

    public RecordLayer(ProtocolVersion version, ConnectionState connectionState) {
        this.version = version;
        this.connectionState = connectionState;
        this.pendingCipherSpec = connectionState.getSecurityParameters();
    }

    public byte[] getClientHello() throws IOException {

        TlsPlaintextRecord record = new TlsPlaintextRecord(FragmentTypes.HANDSHAKE, version);

        ClientHello clientHello = new ClientHello();
        clientHello.setClientRandom(pendingCipherSpec.getClientRandom());
        if (sessionId != null) {
            clientHello.setSessionId(sessionId);
        }
        clientHello.setCipherSuites(currentCipherSuites != null ? currentCipherSuites : CipherSuites.defaultCipherSuites);
        clientHello.setExtensions(currentTlsExtensions != null ? currentTlsExtensions : Extensions.defaultExtensions);

        HandshakeFragment handshakeFragment = new HandshakeFragment(HandshakeMessageTypes.CLIENT_HELLO, clientHello);
        record.setFragment(handshakeFragment);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        return record.encode();
    }

    public byte[] getAlert(byte alertLevel, byte alertDescription) {
        return new byte[0];
    }

    public TlsPlaintextRecord readPlaintextRecord(ConnectionManager connectionManager)
            throws IOException, RecordLayerException {

        ByteBuffer buffer = ByteBuffer.allocate(5);
        Future<Integer> future = connectionManager.read(buffer);
        try {
            Integer length = future.get();
            if (length != 5) {
                throw new RecordLayerException("Failed to read record header");
            }
            buffer.flip();
            TlsPlaintextRecord record = new TlsPlaintextRecord(buffer.get(),
                    new ProtocolVersion(buffer.get(), buffer.get()));
            short fragmentLength = buffer.getShort();
            buffer = ByteBuffer.allocate(fragmentLength);
            future = connectionManager.read(buffer);
            length = future.get();
            if (length.shortValue() != fragmentLength) {
                throw new RemoteException("Failed to read fragment");
            }
            buffer.flip();
            // We're going through all of this thrashing around because ByteBuffer
            // isn't really meant for what we're doing.
            byte[] recordBytes = new byte[length];
            buffer.get(recordBytes);
            record.decode(recordBytes);
            return record;
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] getClientKeyExchange() {
        return new byte[0];
    }

    public void setCurrentExtensions(final List<TlsExtension> currentTlsExtensions) {
        this.currentTlsExtensions = currentTlsExtensions;
    }

    public List<Short> getCurrentCipherSuites() {
        return currentCipherSuites;
    }

    public void setCurrentCipherSuites(List<Short> cipherSuites) {
        currentCipherSuites = cipherSuites;
    }
}
