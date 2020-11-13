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

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHAgreement;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.secomm.tls.crypto.CipherSuiteTranslator;
import org.secomm.tls.crypto.cipher.RSACipher;
import org.secomm.tls.crypto.signature.SignedDigest;
import org.secomm.tls.crypto.signature.SignedDigestFactory;
import org.secomm.tls.protocol.record.handshake.ClientKeyExchange;
import org.secomm.tls.protocol.record.handshake.ServerKeyExchange;
import org.secomm.tls.util.EncodingByteBuffer;

import java.math.BigInteger;
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

    private CipherSuiteTranslator.KeyExchangeAlgorithm keyExchangeAlgorithm;

    private BigInteger dhPrivateKey;

    private BigInteger dhPublicKey;

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

    public boolean isSigned() {
        return keyExchangeAlgorithm == CipherSuiteTranslator.KeyExchangeAlgorithm.DHE_RSA
                || keyExchangeAlgorithm == CipherSuiteTranslator.KeyExchangeAlgorithm.DHE_DSS;
    }

    public ClientKeyExchange generateClientKeyExchange()
            throws InvalidKeyException {

        ClientKeyExchange clientKeyExchange = new ClientKeyExchange();
        if (keyExchangeAlgorithm == CipherSuiteTranslator.KeyExchangeAlgorithm.RSA) {
            clientKeyExchange.setPremasterSecret(generateRSAPremasteredSecret());
        } else {
            clientKeyExchange.setClientPublicKey(generateDHPublicKey());
        }
        return clientKeyExchange;
    }

    private byte[] generateRSAPremasteredSecret() throws InvalidKeyException {

        byte[] premasterRandom = new byte[46];
        random.nextBytes(premasterRandom);
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(48);
        buffer.put(supportedVersion);
        buffer.put(premasterRandom);
        byte[] secretBytes =  buffer.toArray();
        RSACipher cipher = new RSACipher();
        cipher.initialize(serverCertificate.getPublicKey());
        return cipher.encrypt(secretBytes);
    }

    private byte[] generateDHPublicKey() {

        // Generate the key pair
        DHKeyPairGenerator generator = new DHKeyPairGenerator();
        // We have to prepend a zero byte so that BigInteger doesn't sign extend
        // if the msb is 1.
        EncodingByteBuffer pBuffer = EncodingByteBuffer.allocate(serverDHParameters.dh_p.length + 1);
        pBuffer.put((byte) 0);
        pBuffer.put(serverDHParameters.dh_p);
        BigInteger p = new BigInteger(pBuffer.toArray());
        // Do the same for the generator in case someone picks something other than 2.
        EncodingByteBuffer gBuffer = EncodingByteBuffer.allocate(serverDHParameters.dh_p.length + 1);
        gBuffer.put((byte) 0);
        gBuffer.put(serverDHParameters.dh_g);
        BigInteger g = new BigInteger(gBuffer.toArray());
//        BigInteger q = p.multiply(BigInteger.TWO).add(BigInteger.ONE);
//        int l = serverDHParameters.dh_p.length * 8;
//        generator.init(new DHKeyGenerationParameters(random, new DHParameters(p, g, q, l)));
        generator.init(new DHKeyGenerationParameters(random, new DHParameters(p, g)));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        dhPrivateKey = ((DHPrivateKeyParameters)keyPair.getPrivate()).getX();
        dhPublicKey = ((DHPublicKeyParameters)keyPair.getPublic()).getY();
        return dhPublicKey.toByteArray();
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

    public void setKeyExchangeAlgorithm(CipherSuiteTranslator.KeyExchangeAlgorithm keyExchangeAlgorithm) {
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }
}
