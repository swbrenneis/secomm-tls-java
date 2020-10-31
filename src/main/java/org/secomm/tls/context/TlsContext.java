package org.secomm.tls.context;

import java.security.SecureRandom;

public class TlsContext {

    public static TlsClientContext initializeClient(SecureRandom random) {
        return new TlsClientContext();
    }

    public static TlsServerContext initializeServer(SecureRandom random) {
        return new TlsServerContext();
    }
}
