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

package org.secomm.tls.net;

import org.secomm.tls.protocol.ConnectionState;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class ClientConnectionManager implements ConnectionManager {

    private AsynchronousSocketChannel channel;

    private final String address;

    private final int port;

    private ByteBuffer lastRead;

    public ClientConnectionManager(String address, int port) {
        this.address = address;
        this.port = port;
    }

    public void connect(CompletionHandler<Void, ClientConnectionManager> connectHandler) throws IOException {
        channel = AsynchronousSocketChannel.open();
        channel.connect(new InetSocketAddress(address, port), this, connectHandler);
    }

    public boolean connect() throws IOException {
        channel = AsynchronousSocketChannel.open();
        Future<Void> future = channel.connect(new InetSocketAddress(address, port));
        try {
            future.get();
            return channel.isOpen();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public void read(int length, CompletionHandler<Integer, ConnectionManager> readHandler) {
        lastRead = ByteBuffer.allocate(length);
        channel.read(lastRead, this, readHandler);
    }

    @Override
    public Future<Integer> read(ByteBuffer buffer) {
        return channel.read(buffer);
    }

    @Override
    public ByteBuffer read() {
        return lastRead;
    }

    @Override
    public void write(ByteBuffer buffer, CompletionHandler<Integer, ConnectionManager> writeHandler) {
        channel.write(buffer, this, writeHandler);
    }

    @Override
    public void close() {
        try {
            channel.close();
        } catch (IOException e) {
            // Java be stupid
            e.printStackTrace();
        }
    }
}
