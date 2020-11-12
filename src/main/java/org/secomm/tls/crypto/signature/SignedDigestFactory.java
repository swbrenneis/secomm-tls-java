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

package org.secomm.tls.crypto.signature;

import org.bouncycastle.crypto.Digest;
import org.secomm.tls.crypto.digest.DigestFactory;
import org.secomm.tls.protocol.SignatureAndHashAlgorithm;
import org.secomm.tls.protocol.TlsConstants;

import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SignedDigestFactory {

    public interface SignatureBuilder <T extends SignatureWithDigest> {
        T build(Digest digest);
    }

    private static final Map<Integer, SignatureBuilder<?>> signatureMap = Stream.of(new Object[][] {
            { (int) TlsConstants.DHE_SIGNATURE_RSA, new RSASignatureWithDigest.Builder() }
    }).collect(Collectors.toMap(e -> (Integer) e[0], e -> (SignatureBuilder<?>) e[1]));

    private static final Map<Integer, String> hashNamesMap = Stream.of(new Object[][] {
            { (int) TlsConstants.DHE_HASH_SHA1, "SHA1" }
    }).collect(Collectors.toMap(e -> (Integer) e[0], e -> (String) e[1]));

    public static SignedDigest getDHESignedDigest(SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws NoSuchAlgorithmException {
        SignatureBuilder<?> signatureBuilder = signatureMap.get(signatureAndHashAlgorithm.getSignatureAlgorithm());
        if (signatureBuilder == null) {
            throw new NoSuchAlgorithmException("Invalid signing algorithm");
        }
        Digest digest = DigestFactory.getDigest(hashNamesMap.get(signatureAndHashAlgorithm.getHashAlgorithm()));
        return signatureBuilder.build(digest);
    }
}
