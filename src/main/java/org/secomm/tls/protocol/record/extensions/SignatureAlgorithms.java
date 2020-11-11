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

public class SignatureAlgorithms extends AbstractTlsExtension {

    public static final class Builder implements ExtensionFactory.ExtensionBuilder<SignatureAlgorithms> {
        @Override
        public SignatureAlgorithms build() {
            return new SignatureAlgorithms();
        }
    }

    public static final class Algorithms {
        public byte hash;
        public byte signature;
        public Algorithms(byte hash, byte signature) {
            this.hash = hash;
            this.signature = signature;
        }
    }

    private List<Algorithms> algorithmsList;

    public SignatureAlgorithms() {
        super(Extensions.SIGNATURE_ALGORITHMS);
    }

    public SignatureAlgorithms(List<Algorithms> algorithmsList) {
        super(Extensions.SIGNATURE_ALGORITHMS);
        this.algorithmsList = algorithmsList;
    }

    @Override
    protected void encodeExtensionData() {

        ByteBuffer data = ByteBuffer.allocate((algorithmsList.size() * 2) + 2);
        data.putShort((short) (algorithmsList.size() * 2));
        for (Algorithms algorithms : algorithmsList) {
            data.put(algorithms.hash);
            data.put(algorithms.signature);
        }
        extensionData = data.array();
    }

    @Override
    protected void decodeExtensionData() {

        ByteBuffer data = ByteBuffer.wrap(extensionData);
        short algorithmsLength = data.getShort();
        algorithmsList = new ArrayList<>();
        while (algorithmsList.size() < algorithmsLength / 2) {
            algorithmsList.add(new Algorithms(data.get(), data.get()));
        }
    }

    @Override
    public String getText() throws InvalidEncodingException {
/*
        String result = "Signature Algorithms\n";
        for (Algorithms algorithms : algorithmsList) {
            String hash = hashNames.get(algorithms.hash);
            if (hash == null) {
                hash = "Invalid";
            }
            String signature = signatureNames.get(algorithms.signature);
            if (signature == null) {
                signature = "Invalid";
            }
            result += "\tHash: " + hash + ", Signature: " + signature + "\n";
        }
*/
        return "";
    }

}
