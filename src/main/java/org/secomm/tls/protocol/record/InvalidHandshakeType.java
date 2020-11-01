package org.secomm.tls.protocol.record;

public class InvalidHandshakeType extends Exception {
    public InvalidHandshakeType(String message) {
        super(message);
    }
}
