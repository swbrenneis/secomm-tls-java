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

import org.secomm.tls.protocol.record.RecordLayer;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

class TlsConversationImpl implements TlsConversation {

    private RecordLayer recordLayer;

    TlsConversationImpl(RecordLayer recordLayer) {
        this.recordLayer = recordLayer;
    }

    public void connect(String address, int port) throws IOException {
        recordLayer.connect(address, port);
    }

    @Override
    public TlsResponse exchange(byte[] payload) throws IOException {
        return null;
    }

    @Override
    public TlsResponse exchange(byte[] payload, long timeout) throws IOException {
        return null;
    }

    @Override
    public TlsResponse exchange(byte[] payload, long timeout, TimeUnit units) throws IOException {
        return null;
    }

    @Override
    public void exchange(byte[] payload, TlsCallback callback) throws IOException {

    }

    @Override
    public void send(byte[] payload) throws IOException {

    }

    @Override
    public TlsResponse exchange(String payload) throws IOException {
        return null;
    }

    @Override
    public TlsResponse exchange(String payload, long timeout) throws IOException {
        return null;
    }

    @Override
    public TlsResponse exchange(String payload, long timeout, TimeUnit units) throws IOException {
        return null;
    }

    @Override
    public void exchange(String payload, TlsCallback callback) throws IOException {

    }

    @Override
    public void send(String payload) throws IOException {

    }

}
