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

package org.secomm.tls.api;

import org.secomm.tls.protocol.ConnectionState;
import org.secomm.tls.protocol.SecurityParameters;
import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.RecordLayerException;
import org.secomm.tls.protocol.record.ServerHello;
import org.secomm.tls.protocol.record.extensions.TlsExtension;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.List;

public class TlsClientContext extends TlsContext {

    private final SecureRandom random;

    private final RecordLayer recordLayer;

    private final ConnectionState connectionState;

    private final SecurityParameters securityParameters;

    private Socket socket;

    TlsClientContext(final SecureRandom random) {
        this.random = random;
        this.securityParameters = new SecurityParameters(SecurityParameters.ConnectionEnd.CLIENT, random);
        this.connectionState = new ConnectionState(securityParameters);
        this.recordLayer = new RecordLayer(RecordLayer.TLS_1_2, connectionState);
    }

    /**
     * Simple connect on default SSL port 443
     *
     * @param address
     * @return TlsPeer if connected, otherwise null
     * @throws IOException
     */
    public TlsPeer connect(String address) throws IOException {
        return connect(address, 443);
    }

    /**
     *
     * @param address
     * @param port
     * @return TlsPeer if connected, otherwise null.
     * @throws IOException
     */
    public TlsPeer connect(String address, int port) throws IOException {
        TlsPeer tlsPeer = new TlsPeerImpl(connectionState);
        socket = new Socket(address, port);
        try {
            doHandshake();
            return tlsPeer;
        } catch (RecordLayerException e) {
            // TODO Something better than this
            e.printStackTrace();
            return null;
        }
    }

    public void setCipherSuites(List<Short> cipherSuites) {
        recordLayer.setCurrentCipherSuites(cipherSuites);
    }

    public void setExtensions(List<TlsExtension> extensions) {
        recordLayer.setCurrentExtensions(extensions);
    }

    private void doHandshake() throws IOException, RecordLayerException {

        connectionState.setCurrentState(ConnectionState.CurrentState.HANDSHAKE_STARTED);
        OutputStream out = socket.getOutputStream();
        byte[] clientHello = recordLayer.getClientHello();
        ServerHello serverHello = recordLayer.getServerHello(socket.getInputStream());
        out.write(clientHello);
    }
}
