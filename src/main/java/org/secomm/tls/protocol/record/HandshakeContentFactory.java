package org.secomm.tls.protocol.record;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class HandshakeContentFactory {

    public interface HandshakeBuilder<T extends AbstractHandshake> {
        public T build(byte[] encoding);
    }

    private static Map<Byte, HandshakeBuilder<?>> handshakeBuilderMap = Stream.of( new Object[][] {
            { AbstractHandshake.CLIENT_HELLO, new ClientHello.Builder() }
    }).collect(Collectors.toMap(e -> (Byte) e[0], e -> (HandshakeBuilder<?>) e[1]));

    public static <T extends AbstractHandshake> T getHandshake(byte handshakeType, byte[] encoding) throws InvalidHandshakeType {
        if (!handshakeBuilderMap.containsKey(handshakeType)) {
            throw new InvalidHandshakeType("Unknown handshake type " + handshakeType);
        }
        return (T) handshakeBuilderMap.get(handshakeType).build(encoding);
    }
}
