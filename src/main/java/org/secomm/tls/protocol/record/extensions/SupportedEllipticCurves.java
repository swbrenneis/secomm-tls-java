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

public class SupportedEllipticCurves extends AbstractExtension {

    public static final class Builder implements ExtensionFactory.ExtensionBuilder<SupportedEllipticCurves> {
        @Override
        public SupportedEllipticCurves build() {
            return new SupportedEllipticCurves();
        }
    }

    private static final Map<Short,String> curveNames = Stream.of(new Object[][] {
            {(short) 1, "sect163k1"}, {(short) 2, "sect163r1"}, {(short) 3, "sect163r2"},
            {(short) 4, "sect193r1"}, {(short) 5, "sect193r2"}, {(short) 6, "sect233k1"},
            {(short) 7, "sect233r1"}, {(short) 8, "sect239k1"}, {(short) 9, "sect283k1"},
            {(short) 10, "sect283r1"}, {(short) 11, "sect409k1"}, {(short) 12, "sect409r1"},
            {(short) 13, "sect571k1"}, {(short) 14, "sect571r1"}, {(short) 15, "secp160k1"},
            {(short) 16, "secp160r1"}, {(short) 17, "secp160r2"}, {(short) 18, "secp192k1"},
            {(short) 19, "secp192r1"}, {(short) 20, "secp224k1"}, {(short) 21, "secp224r1"},
            {(short) 22, "secp256k1"}, {(short) 23, "secp256r1"}, {(short) 24, "secp384r1"},
            {(short) 25, "secp521r1"},
            {(short) 0xFF01, "arbitrary explicit prime curves"},
            {(short) 0xFF02, "arbitrary explicit char2 curves"}
    }).collect(Collectors.toMap(e -> (short) e[0], e -> (String) e[1]));

    private List<Short> curves;

    public SupportedEllipticCurves() {
        super(Extensions.SUPPORTED_ELLIPTIC_CURVES);
    }

    public SupportedEllipticCurves(List<Short> curves) {
        super(Extensions.SUPPORTED_ELLIPTIC_CURVES);
        this.curves = curves;
    }

    @Override
    protected void encodeExtensionData() throws IOException {
        ByteBuffer data = ByteBuffer.allocate(curves.size() + 2);
        data.putShort((short) curves.size());
        for (short curve : curves) {
            data.putShort(curve);
        }
        extensionData = data.array();
    }

    @Override
    protected void decodeExtensionData() {
        ByteBuffer data = ByteBuffer.wrap(extensionData);
        short curvesSize = data.getShort();
        curves = new ArrayList<>();
        while (curves.size() < curvesSize / 2) {
            curves.add(data.getShort());
        }
    }

    @Override
    public String getText() throws InvalidEncodingException {
        String result = "Supported Elliptic Curves\n";
        for (short curve : curves) {
            String f = curveNames.get(curve);
            if (f == null) {
                f = "unknown(" + curve + ")";
            }
            result += "\t" + f + "\n";
        }
        return result;
    }

    public void setCurves(List<Short> curves) {
        this.curves = curves;
    }
}
