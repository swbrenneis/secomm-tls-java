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

import org.secomm.tls.net.ClientConnectionManager;
import org.secomm.tls.protocol.ClientHandshake;
import org.secomm.tls.protocol.ConnectionState;
import org.secomm.tls.protocol.SecurityParameters;
import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.extensions.TlsExtension;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class TlsClientContext extends TlsContext {

    private final SecureRandom random;

    private final ConnectionState connectionState;

    private final SecurityParameters securityParameters;

    private List<TlsExtension> extensions;

    private List<Short> cipherSuites;

    private TlsPeer peer;

    TlsClientContext(final SecureRandom random) {
        this.random = random;
        this.securityParameters = new SecurityParameters(SecurityParameters.ConnectionEnd.CLIENT, random);
        this.connectionState = new ConnectionState(securityParameters);
        // Created here to be available if there are no extensions or cipherSuites (unlikely)
        extensions = new ArrayList<>();
        cipherSuites = new ArrayList<>();
    }

    /**
     * Simple connect on default SSL port 443
     *
     * @param address
     * @return TlsPeer if connected, otherwise null
     * @throws IOException
     */
    public TlsPeer connect(String address) throws IOException {
        connect(address, 443);
        return peer;
    }

    /**
     *
     * @param address
     * @param port
     * @return TlsPeer if connected, otherwise null.
     * @throws IOException
     */
    public TlsPeer connect(String address, int port) throws IOException {
        ClientConnectionManager connectionManager = new ClientConnectionManager(address, port);
        RecordLayer recordLayer = new RecordLayer(RecordLayer.TLS_1_2, connectionState, connectionManager);
        boolean isOpen = connectionManager.connect();
        if (isOpen) {
            ClientHandshake clientHandshake = new ClientHandshake(connectionState, recordLayer, random);
            clientHandshake.setCipherSuites(cipherSuites);
            clientHandshake.setExtensions(extensions);
            return clientHandshake.doHandshake();
        } else {
            return null;
        }
    }

    public void setCipherSuites(List<Short> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public void setExtensions(List<TlsExtension> extensions) {
        this.extensions = extensions;
    }

}
