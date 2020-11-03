package org.secomm.tls.protocol.record.extensions;

public class InvalidExtensionTypeException extends Exception {
    public InvalidExtensionTypeException(String message) {
        super(message);
    }
}
