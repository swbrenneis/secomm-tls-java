/*
 * Copyright (c) 2020 Steve Brenneis.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following
 * conditions: The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMEN. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 */

package org.secomm.tls.protocol.record.handshake;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class HandshakeMessageFactory {

    public interface HandshakeBuilder<T extends TlsHandshakeMessage> {
        public T build();
    }

    private static final Map<Byte, HandshakeBuilder<?>> handshakeBuilderMap = Stream.of( new Object[][] {
            { HandshakeMessageTypes.CLIENT_HELLO, new ClientHello.Builder() },
            { HandshakeMessageTypes.SERVER_HELLO, new ServerHello.Builder() },
            { HandshakeMessageTypes.CERTIFICATE, new ServerCertificate.Builder() },
            { HandshakeMessageTypes.SERVER_KEY_EXCHANGE, new ServerKeyExchange.Builder() },
            { HandshakeMessageTypes.SERVER_HELLO_DONE, new ServerHelloDone.Builder() },
            { HandshakeMessageTypes.CLIENT_KEY_EXCHANGE, new ClientKeyExchange.Builder() }
    }).collect(Collectors.toMap(e -> (Byte) e[0], e -> (HandshakeBuilder<?>) e[1]));

    public static <T extends TlsHandshakeMessage> T getHandshake(byte handshakeType) throws InvalidHandshakeMessageType {
        if (!handshakeBuilderMap.containsKey(handshakeType)) {
            throw new InvalidHandshakeMessageType("Unknown handshake type " + handshakeType);
        }
        return (T) handshakeBuilderMap.get(handshakeType).build();
    }
}
