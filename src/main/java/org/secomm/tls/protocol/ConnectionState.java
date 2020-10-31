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
