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

package org.secomm.tls.crypto.digest;

import org.bouncycastle.crypto.Digest;

import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DigestFactory {

    /**
     * The generic isn't actually necessary here. It's just used as
     * a type safety measure.
     *
     * @param <T>
     */
    public interface DigestBuilder <T extends Digest> {
        T build();
    }

    private static final Map<String, DigestBuilder<?>> digestMap = Stream.of(new Object[][] {
            { "SHA1", new SHA1DigestWrapper.Builder() }
    }).collect(Collectors.toMap(e -> (String) e[0], e -> (DigestBuilder<?>) e[1]));

    public static Digest getDigest(String algorithm) throws NoSuchAlgorithmException {
        DigestBuilder<?> builder = digestMap.get(algorithm);
        if (builder == null) {
            throw new NoSuchAlgorithmException("Invalid algorithm " + algorithm);
        }
        return builder.build();
    }

}
