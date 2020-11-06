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
import java.nio.charset.Charset;

public interface TlsPeer {

    /**
     * Read the full peer message as a UTF-8 encoded string.
     *
     * @return
     * @throws IOException
     */
    String readAll() throws IOException;

    /**
     * Read the full peer message as a string encoded in the specified format.
     *
     * @param charset
     * @return
     * @throws IOException
     */
    String readAll(String charset) throws IOException;

    /**
     * Read the full peer message as a string encoded in the specified format.
     *
     * @param charset
     * @return
     * @throws IOException
     */
    String readAll(Charset charset) throws IOException;

    /**
     * Read bytes from
     * @param bytes
     * @throws IOException
     */
    void read(byte[] bytes) throws IOException;

    /**
     * Send a message as a UTF-8 encoded string
     * @param message
     * @throws IOException
     */
    void write(String message) throws IOException;

    /**
     * Send a message as a string in the specified encoding.
     * @param message
     * @param charset
     * @throws IOException
     */
    void write(String message, String charset) throws IOException;

    /**
     * Send a message as a string in the specified encoding.
     * @param message
     * @param charset
     * @throws IOException
     */
    void write(String message, Charset charset) throws IOException;

    /**
     * Send a message as raw bytes.
     *
     * @param bytes
     * @throws IOException
     */
    void write(byte[] bytes) throws IOException;

    /**
     * Get the encrypted input stream.
     *
     * @return
     */
    TlsInputStream getInputStream();

    /**
     * Get the encrypted output stream
     *
     * @return
     */
    TlsOutputStream getOutputStream();

    /**
     * Use the conversation interface.
     *
     * @return
     */
    TlsConversation getConversation();
}
