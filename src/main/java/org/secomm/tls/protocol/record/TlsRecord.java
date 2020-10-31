package org.secomm.tls.protocol.record;

import org.secomm.tls.protocol.record.TlsFragment;

public abstract class TlsRecord {

    /**
     * Content types
     */
    public static final byte CHANGE_CIPHER_SPEC = 20;
    public static final byte ALERT = 21;
    public static final byte HANDSHAKE = 22;
    public static final byte APPLICATION_DATA = 23;

    protected byte contentType;

    protected RecordLayer.ProtocolVersion version;

    protected TlsFragment fragment;

    protected TlsRecord(byte contentType, RecordLayer.ProtocolVersion version) {
        this.contentType = contentType;
        this.version = version;
    }

    protected TlsRecord() {

    }

    public byte getContentType() {
        return contentType;
    }

    public RecordLayer.ProtocolVersion getVersion() {
        return version;
    }

    public TlsFragment getFragment() {
        return fragment;
    }

    public void setFragment(TlsFragment fragment) {
        this.fragment = fragment;
    }
}
