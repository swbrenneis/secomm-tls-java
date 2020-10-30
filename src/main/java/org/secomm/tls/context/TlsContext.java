package org.secomm.tls.context;

public class TlsContext {

    public static TlsClientContext initializeClient() {
        return new TlsClientContext();
    }

    public static TlsServerContext initializeServer() {
        return new TlsServerContext();
    }
}
