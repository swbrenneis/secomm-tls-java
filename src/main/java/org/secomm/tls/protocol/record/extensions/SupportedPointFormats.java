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

import org.secomm.tls.protocol.record.InvalidEncodingException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SupportedPointFormats extends AbstractExtension {

    public static final class Builder implements ExtensionFactory.ExtensionBuilder<SupportedPointFormats> {
        @Override
        public SupportedPointFormats build() {
            return new SupportedPointFormats();
        }
    }

    private static final Map<Byte,String> formatNames = Stream.of(new Object[][] {
            { (byte) 0, "Uncompressed" },
            { (byte) 1, "ANSI X962 compressed prime" },
            { (byte) 2, "ANSI X962 compressed char 2" }
    }).collect(Collectors.toMap(e -> (byte) e[0], e -> (String) e[1]));

    private List<Byte> formats;

    public SupportedPointFormats() {
        super(Extensions.SUPPORTED_POINT_FORMATS);
    }

    public SupportedPointFormats(List<Byte> formats) {
        super(Extensions.SUPPORTED_POINT_FORMATS);
        this.formats = formats;
    }

    @Override
    protected void encodeExtensionData() throws IOException {
        ByteBuffer data = ByteBuffer.allocate(formats.size() + 2);
        data.put((byte) formats.size());
        for (byte format : formats) {
            data.put(format);
        }
        extensionData = data.array();
    }

    @Override
    protected void decodeExtensionData() {
        ByteBuffer data = ByteBuffer.wrap(extensionData);
        byte formatSize = data.get();
        formats = new ArrayList<>();
        while (formats.size() < formatSize) {
            formats.add(data.get());
        }
    }

    @Override
    public String getText() throws InvalidEncodingException {
        String result = "Supported Point Formats\n";
        for (Byte format : formats) {
            result += "\t" + formatNames.get(format) + "\n";
        }
        return result;
    }

    public void setFormats(List<Byte> formats) {
        this.formats = formats;
    }
}
