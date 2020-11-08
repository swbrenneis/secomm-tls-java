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
import org.secomm.tls.net.ClientConnectionManager;
import org.secomm.tls.net.ConnectionManager;
import org.secomm.tls.protocol.record.FragmentTypes;
import org.secomm.tls.protocol.record.HandshakeFragment;
import org.secomm.tls.protocol.record.HandshakeTypes;
import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.RecordLayerException;
import org.secomm.tls.protocol.record.ServerHello;
import org.secomm.tls.protocol.record.TlsFragment;
import org.secomm.tls.protocol.record.TlsHandshake;
import org.secomm.tls.protocol.record.TlsPlaintextRecord;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
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

    public ClientHandshake(final ClientConnectionManager connectionManager,
                           final ConnectionState connectionState,
                           final RecordLayer recordLayer) {
        this.connectionManager = connectionManager;
        this.connectionState = connectionState;
        this.recordLayer = recordLayer;
        this.executor = Executors.newSingleThreadExecutor();
        this.peerLock = new ReentrantLock();
        this.peerCondition = peerLock.newCondition();
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
                signalComplete();
            }
            TlsHandshake handshake = ((HandshakeFragment) fragment).getHandshake();
            if (handshake.getHandshakeType() != HandshakeTypes.SERVER_HELLO) {
                reason = new RecordLayerException("Not a handshake fragment");
                signalComplete();
            }
            evaluateServerHello((ServerHello) handshake);
        } catch (IOException | RecordLayerException e) {
            e.printStackTrace();
            signalComplete();
        }
    }

    private void evaluateServerHello(ServerHello serverHello) {

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
