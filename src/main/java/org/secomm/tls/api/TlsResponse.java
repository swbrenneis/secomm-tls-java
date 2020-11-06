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

import java.nio.charset.Charset;

/**
 * Encapsulates the response in a Tls exchange.
 */
public interface TlsResponse {

    /**
     * Test validity of the response. If this returns false,
     * call getErrorInfo for further information.
     *
     * @return True if the response is ready and there were no errors
     */
    boolean isReady();

    /**
     * Provides error information.
     *
     * @return The error information or null if there was no error.
     */
    String getErrorInfo();

    /**
     * Get the raw byte array response
     *
     * @return
     */
    byte[] getBytes();

    /**
     * Get the response as a UTF-8 string
     *
     * @return
     */
    String toString();

    /**
     * Get the response as a string in the given encoding
     *
     * @param charset
     * @return
     */
    String toString(Charset charset);

    /**
     * Get the response as a string in the given encoding.
     *
     * @param charset
     * @return
     */
    String toString(String charset);

    /**
     * Copy bytes from the source response to a destination array.
     * Does not throw exceptions.
     *
     * @param srcOffset
     * @param destination
     * @param offset
     * @param length
     * @return The number of bytes copied. May be less than the length parameter.
     */
    long copyBytes(int srcOffset, byte[] destination, int offset, int length);

}
