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

import javax.crypto.SecretKey;

public class ConnectionState {

    public enum CurrentState { INITIALIZING, HANDSHAKE_STARTED, HANDSHAKE_COMPLETE, RENEGOTIATING, CLOSED }

    private CurrentState currentState;

    /**
     * Per the RFC, this contains the current scheduled
     * key and stream cipher state data.
     */
    public static final class CipherState {
        public SecretKey scheduledKey;
    }

    private CipherState cipherState;

    private byte[] macKey;

    private SecurityParameters securityParameters;

    /**
     * Current record sequence number.
     */
    private long sequenceNumber;

    public ConnectionState(SecurityParameters securityParameters) {
        this.securityParameters = securityParameters;
        this.currentState = CurrentState.INITIALIZING;
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

    public CurrentState getCurrentState() {
        return currentState;
    }

    public void setCurrentState(CurrentState currentState) {
        this.currentState = currentState;
    }

    public SecurityParameters getSecurityParameters() {
        return securityParameters;
    }
}
