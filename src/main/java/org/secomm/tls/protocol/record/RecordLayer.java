package org.secomm.tls.protocol.record;

import org.secomm.tls.protocol.SecurityParameters;

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

    private SecurityParameters pendingCipherSpec;

    private SecurityParameters currentCipherSpec;

    public RecordLayer(ProtocolVersion version) {
        this.version = version;
    }

    public void sendClientHello() {

        ClientHello clientHello = new ClientHello();
//        clientHello.setRandom((int) (System.currentTimeMillis() / 1000),);
    }

}
