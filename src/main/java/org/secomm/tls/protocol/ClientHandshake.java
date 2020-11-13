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
import org.secomm.tls.crypto.CipherSuiteTranslator;
import org.secomm.tls.crypto.cipher.RSACipher;
import org.secomm.tls.crypto.signature.RSASignatureWithDigest;
import org.secomm.tls.protocol.record.AlertFragment;
import org.secomm.tls.protocol.record.RecordLayerException;
import org.secomm.tls.protocol.record.extensions.TlsExtension;
import org.secomm.tls.protocol.record.handshake.CertificateRequest;
import org.secomm.tls.protocol.record.handshake.CertificateVerify;
import org.secomm.tls.protocol.record.handshake.ClientHello;
import org.secomm.tls.protocol.record.handshake.ClientKeyExchange;
import org.secomm.tls.protocol.record.handshake.Finished;
import org.secomm.tls.protocol.record.HandshakeFragment;
import org.secomm.tls.protocol.record.handshake.HandshakeMessageTypes;
import org.secomm.tls.protocol.record.handshake.HelloRequest;
import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.handshake.ServerCertificate;
import org.secomm.tls.protocol.record.handshake.ServerHello;
import org.secomm.tls.protocol.record.handshake.ServerHelloDone;
import org.secomm.tls.protocol.record.handshake.ServerKeyExchange;
import org.secomm.tls.protocol.record.handshake.TlsHandshakeMessage;
import org.secomm.tls.protocol.record.TlsPlaintextRecord;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.List;

public class ClientHandshake {

    private enum HandshakeStep { NOT_STARTED, HELLO_REQUEST, CLIENT_HELLO, SERVER_HELLO, SERVER_CERTIFICATE,
        SERVER_KEY_EXCHANGE, CERTIFICATE_REQUEST, SERVER_HELLO_DONE, CERTIFICATE_VERIFY, CLIENT_KEY_EXCHANGE,
        SERVER_FINISHED, CLIENT_FINISHED }

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

    private final ConnectionState connectionState;

    private final RecordLayer recordLayer;

    private TlsPeer peer;

    private Throwable reason;

    private CipherSuiteTranslator.KeyExchangeAlgorithm keyExchangeAlgorithm;

    private final KeyExchangeEngine keyExchangeEngine;

    private final HandshakeMessages handshakeMessages;

    private HandshakeStep handshakeStep;

    private List<TlsExtension> extensions;

    private List<Short> cipherSuites;

    private short cipherSuite;

    private final SecureRandom random;

    public ClientHandshake(final ConnectionState connectionState,
                           final RecordLayer recordLayer,
                           final SecureRandom random) {
        this.connectionState = connectionState;
        this.recordLayer = recordLayer;
        this.keyExchangeEngine = new KeyExchangeEngine(connectionState.getSecurityParameters(), random);
        this.handshakeMessages = new HandshakeMessages();
        this.random = random;
        handshakeStep = HandshakeStep.NOT_STARTED;
    }

    public TlsPeer doHandshake() {
        peer = null;
        startHandshake();
        return peer;
    }

    /**
     * Start the Tls handshake. The purpose of this method is to
     * handle handshake exceptions.
     */
    private void startHandshake() {
        try {
            sendClientHello();
        } catch (HandshakeException e) {
            sendFatalAlert(e.getAlertDescription());
        }
    }

    private void sendClientHello() throws HandshakeException {

        ClientHello clientHello = new ClientHello();
        clientHello.setCipherSuites(cipherSuites);
        clientHello.setExtensions(extensions);
        byte[] clientRandom = new byte[32];
        random.nextBytes(clientRandom);
        clientHello.setClientRandom(clientRandom);
        keyExchangeEngine.setClientRandom(clientRandom);
        recordLayer.sendHandshakeRecord(clientHello);
        handshakeStep = HandshakeStep.CLIENT_HELLO;
        nextRecord();
    }

    private void nextRecord() throws HandshakeException {

        try {
            TlsPlaintextRecord record = recordLayer.readPlaintextRecord();
            HandshakeFragment fragment = record.getFragment();
            TlsHandshakeMessage handshakeMessage = fragment.getHandshakeMessage();
            switch (handshakeMessage.getHandshakeType()) {
                case HandshakeMessageTypes.SERVER_HELLO:
                    if (handshakeStep == HandshakeStep.CLIENT_HELLO) {
                        ServerHello serverHello = (ServerHello) handshakeMessage;
                        processServerHello(serverHello);
                    } else {
                        throw new HandshakeException(AlertFragment.UNEXPECTED_MESSAGE);
                    }
                    break;
                case HandshakeMessageTypes.CERTIFICATE:
                    if (handshakeStep == HandshakeStep.SERVER_HELLO) {
                        ServerCertificate serverCertificate = (ServerCertificate) handshakeMessage;
                        processServerCertificate(serverCertificate);
                    } else {
                        throw new HandshakeException(AlertFragment.UNEXPECTED_MESSAGE);
                    }
                    break;
                case HandshakeMessageTypes.SERVER_KEY_EXCHANGE:
                    // TODO More testing here
                    if (handshakeStep == HandshakeStep.SERVER_HELLO || handshakeStep == HandshakeStep.SERVER_CERTIFICATE) {
                        ServerKeyExchange serverKeyExchange = (ServerKeyExchange) handshakeMessage;
                        processServerKeyExchange(serverKeyExchange);
                    } else {
                        throw new HandshakeException(AlertFragment.UNEXPECTED_MESSAGE);
                    }
                    break;
                case HandshakeMessageTypes.SERVER_HELLO_DONE:
                    if (handshakeStep == HandshakeStep.SERVER_KEY_EXCHANGE || handshakeStep == HandshakeStep.SERVER_CERTIFICATE) {
                        handshakeMessages.serverHelloDone = (ServerHelloDone) handshakeMessage;
                        handshakeStep = HandshakeStep.SERVER_HELLO_DONE;
                        startClientResponse();
                    } else {
                        throw new HandshakeException(AlertFragment.UNEXPECTED_MESSAGE);
                    }
                    break;
                case HandshakeMessageTypes.CERTIFICATE_REQUEST:
                    CertificateRequest certificateRequest = (CertificateRequest) handshakeMessage;
                    processCertificateRequest(certificateRequest);
                    break;
                // Something really bad happened
                default:
                    throw new HandshakeException(AlertFragment.UNEXPECTED_MESSAGE);
            }
        } catch (IOException | RecordLayerException e) {
            reason = e;
            throw new HandshakeException(AlertFragment.INTERNAL_ERROR);
        }
    }

    private void startClientResponse() throws HandshakeException {

        try {
            if (keyExchangeEngine.isSigned() && !keyExchangeEngine.verifySignatureWithHash()) {
                    throw new HandshakeException(AlertFragment.DECRYPT_ERROR);
            }
            byte[] premasterSecret = keyExchangeEngine.generatePremasterSecret();
            ClientKeyExchange clientKeyExchange = new ClientKeyExchange(premasterSecret);
            if  (keyExchangeAlgorithm == CipherSuiteTranslator.KeyExchangeAlgorithm.RSA) {
                clientKeyExchange = new ClientKeyExchange();
            } else {

            }
            recordLayer.sendHandshakeRecord(clientKeyExchange);
        } catch (HandshakeException e) {
            throw e;
        } catch (Exception e) {
            reason = e;
            throw new HandshakeException(AlertFragment.HANDSHAKE_FAILURE);
        }
    }

    private void processServerHello(ServerHello serverHello) throws HandshakeException {
        try {
            handshakeMessages.serverHello = serverHello;
            keyExchangeEngine.setServerRandom(serverHello.getServerRandom());
            cipherSuite = serverHello.getCipherSuite();
            CipherSuiteTranslator.setSecurityParameters(connectionState.getSecurityParameters(), cipherSuite);
            keyExchangeAlgorithm = CipherSuiteTranslator.getKeyExchangeAlgorithm(cipherSuite);
            keyExchangeEngine.setKeyExchangeAlgorithm(keyExchangeAlgorithm);
            handshakeStep = HandshakeStep.SERVER_HELLO;
            nextRecord();
        } catch (UnknownCipherSuiteException e) {
            reason = e;
            throw new HandshakeException(AlertFragment.HANDSHAKE_FAILURE);
        }
    }

    private void processServerCertificate(ServerCertificate serverCertificate) throws HandshakeException {
        try {
            handshakeMessages.serverCertificate = serverCertificate;
            keyExchangeEngine.setServerCertificate(serverCertificate.getCertificate(0));
            handshakeStep = HandshakeStep.SERVER_CERTIFICATE;
            nextRecord();
        } catch (CertificateException e) {
            reason = e;
            throw new HandshakeException(AlertFragment.HANDSHAKE_FAILURE);
        }
    }

    private void processServerKeyExchange(ServerKeyExchange serverKeyExchange) throws HandshakeException {
        handshakeMessages.serverKeyExchange = serverKeyExchange;
        keyExchangeEngine.setSignatureAndHashAlgorithm(serverKeyExchange.getSignatureAndHashAlgorithm());
        keyExchangeEngine.setServerDHParameters(serverKeyExchange.getServerDHParameters());
        keyExchangeEngine.setDhParametersSignature(serverKeyExchange.getSignature());
        handshakeStep = HandshakeStep.SERVER_KEY_EXCHANGE;
        nextRecord();
    }

    private void processCertificateRequest(CertificateRequest certificateRequest) throws HandshakeException {
        handshakeMessages.certificateRequest = certificateRequest;
        handshakeStep = HandshakeStep.CERTIFICATE_REQUEST;
        nextRecord();
    }

    private void setServerCertificateChain(ServerCertificate serverCertificate) {

    }

    private void sendFatalAlert(byte alertDescription) {
        AlertFragment alertFragment = new AlertFragment(AlertFragment.FATAL, alertDescription);
        recordLayer.sendAlertRecord(alertFragment);
    }

    public Throwable getReason() {
        return reason;
    }

    public void setExtensions(List<TlsExtension> extensions) {
        this.extensions = extensions;
    }

    public void setCipherSuites(List<Short> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }
}
