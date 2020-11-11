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
import org.secomm.tls.crypto.CipherStateTranslator;
import org.secomm.tls.crypto.KeyExchangeEngine;
import org.secomm.tls.net.ClientConnectionManager;
import org.secomm.tls.net.ConnectionManager;
import org.secomm.tls.protocol.record.AlertFragment;
import org.secomm.tls.protocol.record.CertificateRequest;
import org.secomm.tls.protocol.record.CertificateVerify;
import org.secomm.tls.protocol.record.ClientHello;
import org.secomm.tls.protocol.record.ClientKeyExchange;
import org.secomm.tls.protocol.record.Finished;
import org.secomm.tls.protocol.record.HandshakeFragment;
import org.secomm.tls.protocol.record.HandshakeMessageTypes;
import org.secomm.tls.protocol.record.HelloRequest;
import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.ServerCertificate;
import org.secomm.tls.protocol.record.ServerHello;
import org.secomm.tls.protocol.record.ServerHelloDone;
import org.secomm.tls.protocol.record.ServerKeyExchange;
import org.secomm.tls.protocol.record.TlsHandshakeMessage;
import org.secomm.tls.protocol.record.TlsPlaintextRecord;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.CompletionHandler;
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

    private final static class HandshakeMessages {
        public HelloRequest helloRequest;
        public ClientHello clientHello;
        public ServerHello serverHello;
        public ServerCertificate serverCertificate;
        public ServerKeyExchange serverKeyExchange;
        public CertificateRequest certificateRequest;
        public ServerHelloDone serverHelloDone;
        public CertificateVerify certificateVerify;
        public ClientKeyExchange clientKeyExchange;
        public Finished clientFinished;
        public Finished serverFinished;
    }

    private final ClientConnectionManager connectionManager;

    private final ConnectionState connectionState;

    private final RecordLayer recordLayer;

    private final ExecutorService executor;

    private TlsPeer peer;

    private final Lock peerLock;

    private final Condition peerCondition;

    private Throwable reason;

    private List<X509Certificate> serverCertificates;

    private CipherStateTranslator.KeyExchangeAlgorithms keyExchangeAlgorithm;

    private final KeyExchangeEngine keyExchangeEngine;

    private final HandshakeMessages handshakeMessages;

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
        this.keyExchangeEngine = new KeyExchangeEngine(connectionState.getSecurityParameters());
        this.handshakeMessages = new HandshakeMessages();
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
            TlsPlaintextRecord record = recordLayer.getClientHello();
            HandshakeFragment fragment = record.getFragment();
            handshakeMessages.clientHello = (ClientHello) fragment.getHandshakeMessage();
            keyExchangeEngine.setClientRandom(handshakeMessages.clientHello.getClientRandom());
            connectionManager.write(ByteBuffer.wrap(record.encode()),
                    new CompletionHandler<Integer, ConnectionManager>() {
                @Override
                public void completed(Integer result, ConnectionManager attachment) {
                    nextRecord();
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

    private void nextRecord() {

        try {
            TlsPlaintextRecord record = recordLayer.readPlaintextRecord(connectionManager);
            HandshakeFragment fragment = record.getFragment();
            TlsHandshakeMessage handshakeMessage = fragment.getHandshakeMessage();
            switch (handshakeMessage.getHandshakeType()) {
                case HandshakeMessageTypes.SERVER_HELLO:
                    ServerHello serverHello = (ServerHello) handshakeMessage;
                    handshakeMessages.serverHello = serverHello;
                    keyExchangeEngine.setServerRandom(serverHello.getServerRandom());
                    short cipherSuite = serverHello.getCipherSuite();
                    CipherStateTranslator.setSecurityParameters(connectionState.getSecurityParameters(), cipherSuite);
                    nextRecord();
                    break;
                case HandshakeMessageTypes.CERTIFICATE:
                    ServerCertificate serverCertificate = (ServerCertificate) handshakeMessage;
                    handshakeMessages.serverCertificate = serverCertificate;
                    keyExchangeEngine.setServerCertificate(serverCertificate.getCertificate(0));
                    nextRecord();
                    break;
                case HandshakeMessageTypes.SERVER_KEY_EXCHANGE:
                    ServerKeyExchange serverKeyExchange = (ServerKeyExchange) handshakeMessage;
                    handshakeMessages.serverKeyExchange = serverKeyExchange;
                    keyExchangeEngine.setKeyExchangeHashAlgorithm(serverKeyExchange.getHashAlgorithm());
                    keyExchangeEngine.setKeyExchangeSignatureAlgorithm(serverKeyExchange.getSignatureAlgorithm());
                    keyExchangeEngine.setServerDHParameters(serverKeyExchange.getServerDHParameters());
                    keyExchangeEngine.setParametersSignatureHash(serverKeyExchange.getParametersSignatureHash());
                    nextRecord();
                    break;
                case HandshakeMessageTypes.SERVER_HELLO_DONE:
                    handshakeMessages.serverHelloDone = (ServerHelloDone) handshakeMessage;
                    startClientResponse();
                    break;
                case HandshakeMessageTypes.CERTIFICATE_REQUEST:
                    handshakeMessages.certificateRequest = (CertificateRequest) handshakeMessage;
                    nextRecord();
                    break;
                // Something really bad happened
                default:
                    sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
                    signalComplete();
            }
        } catch (Exception e) {
            e.printStackTrace();
            reason = e;
            sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
            signalComplete();
        }
    }

    private void startClientResponse() {

        try {
            short cipherSuite = handshakeMessages.serverHello.getCipherSuite();
            byte[] premasterSecret = new byte[0];
            if (keyExchangeEngine.isSigned(cipherSuite)) {
                if (keyExchangeEngine.verifySignatureWithHash()) {
                    premasterSecret = keyExchangeEngine.generatePremasterSecret();
                } else {
                    sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
                    signalComplete();
                }
            } else {
                premasterSecret = keyExchangeEngine.generatePremasterSecret();
            }
        } catch (Exception e) {
            reason = e;
            e.printStackTrace();
            sendFatalAlert(AlertFragment.HANDSHAKE_FAILURE);
            signalComplete();
        }
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
