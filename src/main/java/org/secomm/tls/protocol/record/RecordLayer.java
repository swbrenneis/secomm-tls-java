package org.secomm.tls.protocol.record;

import org.secomm.tls.crypto.Algorithms;
import org.secomm.tls.protocol.CipherSuites;
import org.secomm.tls.protocol.SecurityParameters;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

    public void sendClientHello(OutputStream out) throws IOException {

        TlsPlaintextRecord record = new TlsPlaintextRecord(TlsRecord.HANDSHAKE, new ProtocolVersion((byte) 0x03, (byte) 0x03));
        ClientHello clientHello = new ClientHello();
        byte[] randomBytes = new byte[ClientHello.CLIENT_RANDOM_LENGTH];
        secureRandom.nextBytes(randomBytes);
        clientHello.setClientRandom(randomBytes);
        clientHello.setCipherSuites(CipherSuites.defaultCipherSuites);

        HandshakeFragmentImpl handshakeFragment = new HandshakeFragmentImpl(AbstractHandshake.CLIENT_HELLO, clientHello);

        out.write(record.getEncoded());
    }

    public TlsPlaintextRecord readRecord(InputStream in) {
        return null;
    }

    private void initializeSecurityParameters() {
        pendingCipherSpec = new SecurityParameters(SecurityParameters.ConnectionEnd.CLIENT);
        pendingCipherSpec.setPrfAlgorithm(Algorithms.getPrfAlgorithm(Algorithms.PrfAlgorithms.TLS_PRF_SHA256));
    }
}
