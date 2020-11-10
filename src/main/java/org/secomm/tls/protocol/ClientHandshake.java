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

package org.secomm.tls.protocol;

import org.secomm.tls.api.TlsPeer;
import org.secomm.tls.crypto.CipherStateBuilder;
import org.secomm.tls.net.ClientConnectionManager;
import org.secomm.tls.net.ConnectionManager;
import org.secomm.tls.protocol.record.AlertFragment;
import org.secomm.tls.protocol.record.FragmentTypes;
import org.secomm.tls.protocol.record.HandshakeFragment;
import org.secomm.tls.protocol.record.HandshakeMessageTypes;
import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.RecordLayerException;
import org.secomm.tls.protocol.record.ServerCertificate;
import org.secomm.tls.protocol.record.ServerHello;
import org.secomm.tls.protocol.record.TlsFragment;
import org.secomm.tls.protocol.record.TlsHandshakeMessage;
import org.secomm.tls.protocol.record.TlsPlaintextRecord;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.CompletionHandler;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class ClientHandshake {

    private final ClientConnectionManager connectionManager;

    private final ConnectionState connectionState;

    private final RecordLayer recordLayer;

    private final ExecutorService executor;

    private TlsPeer peer;

    private final Lock peerLock;

    private final Condition peerCondition;

    private Throwable reason;

    private List<X509Certificate> serverCertificates;

    public ClientHandshake(final ClientConnectionManager connectionManager,
                           final ConnectionState connectionState,
                           final RecordLayer recordLayer) {
        this.connectionManager = connectionManager;
        this.connectionState = connectionState;
        this.recordLayer = recordLayer;
        this.executor = Executors.newSingleThreadExecutor();
        this.peerLock = new ReentrantLock();
        this.peerCondition = peerLock.newCondition();
        this.serverCertificates = new ArrayList<>();
    }

    public Future<TlsPeer> doHandshake() {
        connectionState.setCurrentState(ConnectionState.CurrentState.HANDSHAKE_STARTED);
        return executor.submit(this::startHandshake);
    }

    private TlsPeer startHandshake() {
        peer = null;
        try {
            connectionManager.connect(new CompletionHandler<Void, ClientConnectionManager>() {
                @Override
                public void completed(Void result, ClientConnectionManager attachment) {
                    sendClientHello();
                }

                @Override
                public void failed(Throwable exc, ClientConnectionManager attachment) {
                    reason = exc;
                    // TODO Maybe logging?
                    signalComplete();
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        peerLock.lock();
        try {
            peerCondition.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            peerLock.unlock();
        }
        return peer;
    }

    private void sendClientHello() {

        try {
            byte[] clientHello = recordLayer.getClientHello();
            connectionManager.write(ByteBuffer.wrap(clientHello), new CompletionHandler<Integer, ConnectionManager>() {
                @Override
                public void completed(Integer result, ConnectionManager attachment) {
                    readServerHello();
                }

                @Override
                public void failed(Throwable exc, ConnectionManager attachment) {
                    reason = exc;
                    signalComplete();
                }
            });
        } catch (IOException e) {
            reason = e;
            signalComplete();
        }
    }

    private void readServerHello() {
        try {
            TlsPlaintextRecord record = recordLayer.readPlaintextRecord(connectionManager);
            TlsFragment fragment = record.getFragment();
            if (fragment.getFragmentType() != FragmentTypes.HANDSHAKE) {
                reason = new RecordLayerException("Not a handshake fragment");
                sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
            }
            TlsHandshakeMessage handshake = ((HandshakeFragment) fragment).getHandshake();
            if (handshake.getHandshakeType() != HandshakeMessageTypes.SERVER_HELLO) {
                reason = new RecordLayerException("Not a handshake fragment");
                sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
            }
            evaluateServerHello((ServerHello) handshake);
        } catch (IOException | RecordLayerException e) {
            e.printStackTrace();
            sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
        }
    }

    private void evaluateServerHello(ServerHello serverHello) {
        SecurityParameters securityParameters = connectionState.getSecurityParameters();
        securityParameters.setServerRandom(serverHello.getServerRandom());
        if (!recordLayer.getCurrentCipherSuites().contains(serverHello.getCipherSuite())) {
            sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
        } else {
            try {
                CipherStateBuilder.setSecurityParameters(securityParameters, serverHello.getCipherSuite());
                nextRecord();
            } catch (UnknownCipherSuiteException | CertificateException | IOException | RecordLayerException e) {
                sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
            }
        }
    }

    private void nextRecord() throws CertificateException, IOException, RecordLayerException {
        TlsPlaintextRecord record = recordLayer.readPlaintextRecord(connectionManager);
        TlsFragment fragment = record.getFragment();
        if (fragment.getFragmentType() != FragmentTypes.HANDSHAKE) {
            sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
        }
        TlsHandshakeMessage handshake = ((HandshakeFragment) fragment).getHandshake();
        switch (handshake.getHandshakeType()) {
            case HandshakeMessageTypes.CERTIFICATE:
                ServerCertificate serverCertificate = (ServerCertificate) handshake;
                serverCertificates = serverCertificate.getCertificates();
                nextRecord();
                break;
            case HandshakeMessageTypes.SERVER_KEY_EXCHANGE:
                nextRecord();
                break;
            case HandshakeMessageTypes.SERVER_HELLO_DONE:
                sendClientKeyExchange();
        }
    }

    private void sendClientKeyExchange() {

        byte[] clientKeyExchange = recordLayer.getClientKeyExchange();
    }

    private void setServerCertificateChain(ServerCertificate serverCertificate) {

    }

    private void sendFatalAlert(byte alertDescription) {
        byte[] alert = recordLayer.getAlert(AlertFragment.FATAL, alertDescription);
        connectionManager.write(ByteBuffer.wrap(alert), new CompletionHandler<Integer, ConnectionManager>() {
            @Override
            public void completed(Integer result, ConnectionManager attachment) {
                attachment.close();
                signalComplete();
            }

            @Override
            public void failed(Throwable exc, ConnectionManager attachment) {
                // Don't care
                attachment.close();
                signalComplete();
            }
        });
    }

    private <T> T waitOnFuture(Future<T> future) {
        try {
            return future.get();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void signalComplete() {
        peerLock.lock();
        try {
            peerCondition.signal();
        } finally {
            peerLock.unlock();
        }
    }

    public Throwable getReason() {
        return reason;
    }
}
