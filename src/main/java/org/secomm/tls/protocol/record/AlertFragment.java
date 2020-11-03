package org.secomm.tls.protocol.record;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;

public class AlertFragment implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<AlertFragment> {
        public AlertFragment build() throws InvalidEncodingException {
            return new AlertFragment();
        }
    }

    // Alert levels
    public static final byte WARNING = 1;
    public static final byte FATAL = 2;

    // Alert descriptions
    public static final byte CLOSE_NOTIFY = 0;
    public static final byte UNEXPECTED_MESSAGE = 10;
    public static final byte BAD_RECORD_MAC = 20;
    public static final byte DECRYPTION_FAILED_RESERVED = 21;
    public static final byte RECORD_OVERFLOW = 22;
    public static final byte DECOMPRESSION_FAILURE = 30;
    public static final byte HANDSHAKE_FAILURE = 40;
    public static final byte NO_CERTIFICATE_RESERVED = 41;
    public static final byte BAD_CERTIFICATE = 42;
    public static final byte UNSUPPORTED_CERTIFICATE = 43;
    public static final byte CERTIFICATE_REVOKED = 44;
    public static final byte CERTIFICATE_EXPIRED = 45;
    public static final byte CERTIFICATE_UNKNOWN = 46;
    public static final byte ILLEGAL_PARAMETER = 47;
    public static final byte UNKNOWN_CA = 48;
    public static final byte ACCESS_DENIED = 49;
    public static final byte DECODE_ERROR = 50;
    public static final byte DECRYPT_ERROR = 51;
    public static final byte EXPORT_RESTRICTION_RESERVED = 60;
    public static final byte PROTOCOL_VERSION = 70;
    public static final byte INSUFFICIENT_SECURITY = 71;
    public static final byte INTERNAL_ERROR = 80;
    public static final byte USER_CANCELED = 90;
    public static final byte NO_RENEGOTIATION = 100;
    public static final byte UNSUPPORTED_EXTENSION = 110;

    private byte alertLevel;

    private byte alertDescription;

    public AlertFragment() {

    }

    public void decode(ByteBuffer buffer) throws IOException {
        alertLevel = buffer.get();
        alertDescription = buffer.get();
    }
    
    @Override
    public void encode(OutputStream out) throws IOException {

        out.write(alertLevel);
        out.write(alertDescription);
    }

    @Override
    public short getLength() {
        return 2;
    }
}
