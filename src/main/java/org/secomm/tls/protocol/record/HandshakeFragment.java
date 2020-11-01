package org.secomm.tls.protocol.record;

public interface HandshakeFragment extends TlsFragment {

    public AbstractHandshake getHandshake();

}
