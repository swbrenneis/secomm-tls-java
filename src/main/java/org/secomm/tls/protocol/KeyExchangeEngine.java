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

package org.secomm.tls.protocol;

import org.secomm.tls.crypto.CipherSuiteTranslator;
import org.secomm.tls.crypto.signature.SignedDigest;
import org.secomm.tls.crypto.signature.SignedDigestFactory;
import org.secomm.tls.protocol.record.handshake.ServerKeyExchange;
import org.secomm.tls.util.EncodingByteBuffer;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;

public class KeyExchangeEngine {

    private static final byte[] supportedVersion = new byte[] { 0x03, 0x03 };

    private byte[] clientRandom;

    private byte[] serverRandom;

    private Certificate serverCertificate;

    private SignatureAndHashAlgorithm signatureAndHashAlgorithm;

    private final SecurityParameters securityParameters;

    private final SecureRandom random;

    private ServerKeyExchange.ServerDHParameters serverDHParameters;

    private byte[] dhParametersSignature;

    public KeyExchangeEngine(final SecurityParameters securityParameters, final SecureRandom random) {
        this.securityParameters = securityParameters;
        this.random = random;
    }

    /**
     *
     * Utility to verify a signed hash. The signature is decrypted using the
     * public key and the message is hashed. If the results are equal, the
     * signature is valid.
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public boolean verifySignatureWithHash() throws Exception {

        EncodingByteBuffer shortBuffer = EncodingByteBuffer.allocate(2);

        SignedDigest signedDigest = SignedDigestFactory.getDHESignedDigest(signatureAndHashAlgorithm);
        signedDigest.initialize(SignedDigest.Activity.VERIFY, serverCertificate.getPublicKey());
        signedDigest.updateDigest(clientRandom);
        signedDigest.updateDigest(serverRandom);
        shortBuffer.putShort((short)serverDHParameters.dh_p.length);
        signedDigest.updateDigest(shortBuffer.toArray());
        signedDigest.updateDigest(serverDHParameters.dh_p);
        shortBuffer.reset();
        shortBuffer.putShort((short)serverDHParameters.dh_g.length);
        signedDigest.updateDigest(shortBuffer.toArray());
        signedDigest.updateDigest(serverDHParameters.dh_g);
        shortBuffer.reset();
        shortBuffer.putShort((short)serverDHParameters.dh_Ys.length);
        signedDigest.updateDigest(shortBuffer.toArray());
        signedDigest.updateDigest(serverDHParameters.dh_Ys);
        return signedDigest.verify(dhParametersSignature);
    }

    public boolean isSigned(short cipherSuite) {
        CipherSuiteTranslator.KeyExchangeAlgorithms algorithm = CipherSuiteTranslator.getKeyExchangeAlgorithm(cipherSuite);
        return algorithm == CipherSuiteTranslator.KeyExchangeAlgorithms.DHE_RSA
                || algorithm == CipherSuiteTranslator.KeyExchangeAlgorithms.DHE_DSS;
    }

    public void setServerCertificate(Certificate serverCertificate) {
        this.serverCertificate = serverCertificate;
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = serverRandom;
    }

    public void setServerDHParameters(ServerKeyExchange.ServerDHParameters serverDHParameters) {
        this.serverDHParameters = serverDHParameters;
    }

    public void setSignatureAndHashAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
    }

    public void setDhParametersSignature(byte[] dhParametersSignature) {
        this.dhParametersSignature = dhParametersSignature;
    }

    public byte[] generatePremasterSecret() {

        byte[] premasterRandom = new byte[46];
        random.nextBytes(premasterRandom);
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(48);
        buffer.put(supportedVersion);
        buffer.put(premasterRandom);
        return buffer.toArray();
    }
}
