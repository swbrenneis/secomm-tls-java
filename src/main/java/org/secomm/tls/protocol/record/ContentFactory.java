package org.secomm.tls.protocol.record;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ContentFactory {

    public interface FragmentBuilder <T extends TlsFragment> {
        public T build(byte[] encoded) throws InvalidEncodingException;
    }

    private static final Map<Byte, FragmentBuilder<?>> contentMap = Stream.of( new Object[][] {
            { TlsRecord.CHANGE_CIPHER_SPEC, new ChangeCipherSpecFragment.Builder() },
            { TlsRecord.ALERT, new AlertFragment.Builder() },
            { TlsRecord.HANDSHAKE, new HandshakeFragment.Builder() },
            { TlsRecord.APPLICATION_DATA, new ApplicationDataFragment.Builder() }
    }).collect(Collectors.toMap(e -> (Byte) e[0], e -> (FragmentBuilder<?>) e[1]));

    public static <T extends TlsFragment> T getContent(byte type, byte[] encoded)
            throws InvalidContentType, InvalidEncodingException {
        if (!contentMap.containsKey(type)) {
            throw new InvalidContentType("Unknown content type " + type);
        }
        // Safe typecast
        return (T) contentMap.get(type).build(encoded);
    }
}
