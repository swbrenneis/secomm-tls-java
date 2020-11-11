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

package org.secomm.tls.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.secomm.tls.protocol.SecurityParameters;
import org.secomm.tls.protocol.record.ServerKeyExchange;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class KeyExchangeEngine {

    // Hashing algorithms
    public static final byte NONE = 0;
    public static final byte MD5 = 1;
    public static final byte SHA1 = 2;
    public static final byte SHA224 = 3;
    public static final byte SHA256 = 4;
    public static final byte SHA384 = 5;
    public static final byte SHA512 = 6;

    // Signature algorithms
    public static final byte ANONYMOUS = 0;
    public static final byte RSA = 1;
    public static final byte DSA = 2;
    public static final byte ECDSA = 3;

    private static final Map<Byte, String> hashNames = Stream.of(new Object[][]{
            { NONE, "none"},
            { MD5, "MD5" },
            { SHA1, "SHA1" },
            { SHA224, "SHA224" },
            { SHA256, "SHA256" },
            { SHA384, "SH3284" },
            { SHA512, "SHA512"}
    }).collect(Collectors.toMap(e -> (Byte) e[0], e -> (String) e[1]));

    private static final Map<Byte, String> signatureNames = Stream.of(new Object[][]{
            { ANONYMOUS, "ANONYMOUS" },
            { RSA, "RSA" },
            { DSA, "DSA" },
            { ECDSA, "ECDSA" }
    }).collect(Collectors.toMap(e -> (Byte) e[0], e -> (String) e[1]));

    private byte[] clientRandom;

    private byte[] serverRandom;

    private Certificate serverCertificate;

    private byte keyExchangeSignatureAlgorithm;

    private byte keyExchangeHashAlgorithm;

    private final SecurityParameters securityParameters;

    private ServerKeyExchange.ServerDHParameters serverDHParameters;

    private byte[] parametersSignatureHash;

    public KeyExchangeEngine(SecurityParameters securityParameters) {
        this.securityParameters = securityParameters;
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

        byte[] signatureValue;
        byte[] hashValue;

/*
            Cipher cipher = Cipher.getInstance(signatureNames.get(keyExchangeSignatureAlgorithm));
            cipher.init(Cipher.DECRYPT_MODE, serverCertificate);
            signatureValue = cipher.doFinal(parametersSignatureHash);
            return Arrays.equals(hashValue, signatureValue);
*/

        MessageDigest digest = MessageDigest.getInstance(hashNames.get(keyExchangeHashAlgorithm));
        digest.update(clientRandom);
        digest.update(serverRandom);
        digest.update(serverDHParameters.dh_p);
        digest.update(serverDHParameters.dh_g);
        digest.update(serverDHParameters.dh_Ys);
        hashValue = digest.digest();

        Signature signature = Signature.getInstance(signatureNames.get(keyExchangeSignatureAlgorithm), new BouncyCastleProvider());
        signature.initVerify(serverCertificate);
        signature.update(hashValue);
        return signature.verify(parametersSignatureHash);
    }

    public boolean isSigned(short cipherSuite) {
        CipherStateTranslator.KeyExchangeAlgorithms algorithm = CipherStateTranslator.getKeyExchangeAlgorithm(cipherSuite);
        return algorithm == CipherStateTranslator.KeyExchangeAlgorithms.DHE_RSA
                || algorithm == CipherStateTranslator.KeyExchangeAlgorithms.DHE_DSS;
    }

    public void setServerCertificate(Certificate serverCertificate) {
        this.serverCertificate = serverCertificate;
    }

    public void setKeyExchangeSignatureAlgorithm(byte keyExchangeSignatureAlgorithm) {
        this.keyExchangeSignatureAlgorithm = keyExchangeSignatureAlgorithm;
    }

    public void setKeyExchangeHashAlgorithm(byte keyExchangeHashAlgorithm) {
        this.keyExchangeHashAlgorithm = keyExchangeHashAlgorithm;
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

    public void setParametersSignatureHash(byte[] parametersSignatureHash) {
        this.parametersSignatureHash = parametersSignatureHash;
    }

    public byte[] generatePremasterSecret() {
        return new byte[0];
    }
}
