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

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public interface TlsConversation {

    // Byte send methods.

    /**
     * Blocking exchange.
     *
     * @param payload
     * @return
     * @throws IOException
     */
    TlsResponse exchange(byte[] payload) throws IOException;

    /**
     * Blocking exchange with timeout in milliseconds
     * @param payload
     * @param timeout
     * @return
     * @throws IOException
     */
    TlsResponse exchange(byte[] payload, long timeout) throws IOException;

    /**
     * Blocking exchange
     *
     * @param payload
     * @param timeout
     * @param units
     * @return
     * @throws IOException
     */
    TlsResponse exchange(byte[] payload, long timeout, TimeUnit units) throws IOException;

    /**
     * Non-blocking exchange. Client implements the TlsCallback interface.
     *
     * @param payload
     * @param callback
     * @throws IOException
     */
    void exchange(byte[] payload, TlsCallback callback) throws IOException;

    /**
     * Send, no response expected
     *
     * @param payload
     * @throws IOException
     */
    void send(byte[] payload) throws IOException;

    // String exchange methods.

    /**
     * Blocking exchange.
     *
     * @param payload
     * @return
     * @throws IOException
     */
    TlsResponse exchange(String payload) throws IOException;

    /**
     * Blocking exchange with timeout in milliseconds
     * @param payload
     * @param timeout
     * @return
     * @throws IOException
     */
    TlsResponse exchange(String payload, long timeout) throws IOException;

    /**
     * Blocking exchange
     *
     * @param payload
     * @param timeout
     * @param units
     * @return
     * @throws IOException
     */
    TlsResponse exchange(String payload, long timeout, TimeUnit units) throws IOException;

    /**
     * Non-blocking exchange. Client implements the TlsCallback interface.
     *
     * @param payload
     * @param callback
     * @throws IOException
     */
    void exchange(String payload, TlsCallback callback) throws IOException;

    /**
     * Send, no response expected
     *
     * @param payload
     * @throws IOException
     */
    void send(String payload) throws IOException;

}
