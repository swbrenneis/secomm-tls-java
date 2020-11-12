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

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.secomm.tls.crypto.TlsCryptoException;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

public class RSASignatureWithDigest implements SignatureWithDigest {

    public static final class Builder implements SignedDigestFactory.SignatureBuilder<RSASignatureWithDigest> {
        @Override
        public RSASignatureWithDigest build(Digest digest) {
            return new RSASignatureWithDigest(digest);
        }
    }

    private Digest digest;

    private RSADigestSigner signer;

    public RSASignatureWithDigest(Digest digest) {
        this.digest = digest;
        signer = new RSADigestSigner(digest);
    }

    @Override
    public void setDigest(Digest digest) {
        this.digest = digest;
        signer = new RSADigestSigner(digest);
    }

    @Override
    public void initialize(Activity activity, PublicKey publicKey) throws InvalidKeyException {
        if (! (publicKey instanceof RSAPublicKey)) {
            throw new InvalidKeyException("Not an RSA key");
        }
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        RSAKeyParameters keyParameters = new RSAKeyParameters(false, rsaPublicKey.getModulus(),
                rsaPublicKey.getPublicExponent());
        signer.init(activity == Activity.SIGN, keyParameters);
    }

    @Override
    public void updateDigest(byte[] message) {
        signer.update(message, 0, message.length);
    }

    @Override
    public byte[] getSignature() throws TlsCryptoException {
        try {
            return signer.generateSignature();
        } catch (CryptoException e) {
            throw new TlsCryptoException("Signature error", e);
        }
    }

    @Override
    public boolean verify(byte[] signature) {
        return signer.verifySignature(signature);
    }

}
