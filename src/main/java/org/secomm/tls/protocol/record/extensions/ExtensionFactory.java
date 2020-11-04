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

package org.secomm.tls.protocol.record.extensions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ExtensionFactory {

    public interface ExtensionBuilder <T extends Extension> {
        public T build();
    }

    private static final Map<Short, ExtensionBuilder<?>> extensionsMap = Stream.of(new Object[][] {
            { Extensions.SERVER_NAME_INDICATION, new ServerNameIndication.Builder() },
            { Extensions.SUPPORTED_POINT_FORMATS, new SupportedPointFormats.Builder() },
            { Extensions.SUPPORTED_ELLIPTIC_CURVES, new SupportedEllipticCurves.Builder() },
            { Extensions.SESSION_TICKET, new SessionTicket.Builder() },
            { Extensions.SIGNATURE_ALGORITHMS, new SignatureAlgorithms.Builder() }
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (ExtensionBuilder<?>) e[1]));

    private static List<Extension> currentExtensions = new ArrayList<>();

    public static <T extends Extension> T getExtension(short extensionType) throws InvalidExtensionTypeException {
        ExtensionBuilder builder = extensionsMap.get(extensionType);
        if (builder == null) {
            throw new InvalidExtensionTypeException("Unknown extension " + extensionType);
        }
        return (T) builder.build();
    }

    public static List<Extension> getCurrentExtensions() {
        return currentExtensions;
    }

    public static void setCurrentExtensions(final List<Extension> currentExtensions) {
        ExtensionFactory.currentExtensions = currentExtensions;
    }

    public static void addExtension(Extension extension) {
        currentExtensions.add(extension);
    }
}
