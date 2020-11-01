package org.secomm.tls.protocol.record;

import org.secomm.tls.crypto.Algorithms;
import org.secomm.tls.protocol.SecurityParameters;

import java.security.SecureRandom;

/**
 * The record layer manages handshaking and keeps track of
 * the current and pending cipher specs. There is one record layer
 * instance per session.
 */
public class RecordLayer {

    public static final class ProtocolVersion {
        public byte majorVersion;
        public byte minorVersion;
        public ProtocolVersion(byte majorVersion, byte minorVersion) {
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
        }
    }

    public static final ProtocolVersion TLS_1_2 = new ProtocolVersion((byte) 0x03, (byte)0x03);

    private final ProtocolVersion version;

    private final SecureRandom secureRandom;

    private SecurityParameters pendingCipherSpec;

    private SecurityParameters currentCipherSpec;

    public RecordLayer(ProtocolVersion version, SecureRandom secureRandom) {
        this.version = version;
        this.secureRandom = secureRandom;
    }

    public void sendClientHello() {

        ClientHello clientHello = new ClientHello();
        byte[] randomBytes = new byte[28];
        secureRandom.nextBytes(randomBytes);
        clientHello.setRandom((int) (System.currentTimeMillis() / 1000), randomBytes);
    }

    private void initializeSecurityParameters() {
        pendingCipherSpec = new SecurityParameters(SecurityParameters.ConnectionEnd.CLIENT);
        pendingCipherSpec.setPrfAlgorithm(Algorithms.getPrfAlgorithm(Algorithms.PrfAlgorithms.TLS_PRF_SHA256));
    }
}
