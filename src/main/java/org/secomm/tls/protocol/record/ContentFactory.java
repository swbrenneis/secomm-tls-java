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

package org.secomm.tls.protocol.record;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ContentFactory {

    public interface FragmentBuilder <T extends TlsFragment> {
        public T build() throws InvalidEncodingException, InvalidHandshakeType;
    }

    private static final Map<Byte, FragmentBuilder<?>> contentMap = Stream.of( new Object[][] {
            { FragmentTypes.CHANGE_CIPHER_SPEC, new ChangeCipherSpecFragment.Builder() },
            { FragmentTypes.ALERT, new AlertFragment.Builder() },
            { FragmentTypes.HANDSHAKE, new HandshakeFragment.Builder() },
            { FragmentTypes.APPLICATION_DATA, new ApplicationDataFragment.Builder() }
    }).collect(Collectors.toMap(e -> (Byte) e[0], e -> (FragmentBuilder<?>) e[1]));

    public static <T extends TlsFragment> T getContent(byte type)
            throws InvalidContentTypeException, InvalidEncodingException, InvalidHandshakeType {
        if (!contentMap.containsKey(type)) {
            throw new InvalidContentTypeException("Unknown content type " + type);
        }
        // Safe typecast
        return (T) contentMap.get(type).build();
    }
}
