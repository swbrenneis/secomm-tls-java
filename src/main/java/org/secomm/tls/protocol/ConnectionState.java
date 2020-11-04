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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
 * EXPRESSOR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMEN.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 */

package org.secomm.tls.protocol;

import javax.crypto.SecretKey;

public class ConnectionState {

    /**
     * Per the RFC, this contains the current scheduled
     * key and stream cipher state data.
     */
    public static final class CipherState {
        public SecretKey scheduledKey;
    }

    private SecurityParameters securityParameters;

    /**
     * This library isn't going to offer compression for TLS 1.2
     * since it has been removed in TLS 1.3. this is here for
     * documentation purposes only. It will always be false;
     */
    private boolean compressionState;

    private CipherState cipherState;

    private byte[] macKey;

    /**
     * Current record sequence number.
     */
    private long sequenceNumber;

    public SecurityParameters getSecurityParameters() {
        return securityParameters;
    }

    public void setSecurityParameters(SecurityParameters securityParameters) {
        this.securityParameters = securityParameters;
    }

    public boolean getCompressionState() {
        return compressionState;
    }

    public CipherState getCipherState() {
        return cipherState;
    }

    public void setCipherState(CipherState cipherState) {
        this.cipherState = cipherState;
    }

    public byte[] getMacKey() {
        return macKey;
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = macKey;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public long incrementSequenceNumber() {
        return ++sequenceNumber;
    }
}
