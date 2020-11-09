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

import java.security.SecureRandom;
import java.util.Arrays;

public class SecurityParameters {

    public enum ConnectionEnd { CLIENT, SERVER }

    public enum PRFAlgorithm { TLS_PRF_SHA256 }

    public enum BulkCipherAlgorithm { NULL, RC4, TRIPLEDES, AES }

    public enum CipherType { STREAM, BLOCK, AEAD }

    public enum MACAlgorithm { NULL, HMAC_MD5, HMAC_SHA1, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512 }

    public enum CompressionMethod { NULL }

    private final ConnectionEnd entity;

    private PRFAlgorithm prfAlgorithm;

    private BulkCipherAlgorithm bulkCipherAlgorithm;

    private CipherType cipherType;

    private byte encryptionKeyLength;

    private byte blockLength;

    private byte fixedIvLength;

    private byte recordIvLength;

    private MACAlgorithm macAlgorithm;

    private byte macLength;

    private byte macKeyLength;

    private CompressionMethod compressionMethod;

    /**
     * Always 48 bytes
     */
    private byte[] masterSecret;

    /**
     * Always 32 bytes
     */
    private byte[] clientRandom;

    /**
     * Always 32 bytes
     */
    private byte[] serverRandom;

    /**
     *
     * @param entity
     */
    public SecurityParameters(ConnectionEnd entity, SecureRandom secureRandom) {
        this.entity = entity;
        byte[] random = new byte[32];
        secureRandom.nextBytes(random);
        if (entity == ConnectionEnd.SERVER) {
            serverRandom = random;
        } else {
            clientRandom = random;
        }
        prfAlgorithm = PRFAlgorithm.TLS_PRF_SHA256;     // The only choice
        compressionMethod = CompressionMethod.NULL;     // Always
    }

    public ConnectionEnd getEntity() {
        return entity;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    public byte[] getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = serverRandom;
    }

    public PRFAlgorithm getPrfAlgorithm() {
        return prfAlgorithm;
    }

    public void setPrfAlgorithm(PRFAlgorithm prfAlgorithm) {
        this.prfAlgorithm = prfAlgorithm;
    }

    public BulkCipherAlgorithm getBulkCipherAlgorithm() {
        return bulkCipherAlgorithm;
    }

    public void setBulkCipherAlgorithm(BulkCipherAlgorithm bulkCipherAlgorithm) {
        this.bulkCipherAlgorithm = bulkCipherAlgorithm;
    }

    public CipherType getCipherType() {
        return cipherType;
    }

    public void setCipherType(CipherType cipherType) {
        this.cipherType = cipherType;
    }

    public byte getEncryptionKeyLength() {
        return encryptionKeyLength;
    }

    public void setEncryptionKeyLength(byte encryptionKeyLength) {
        this.encryptionKeyLength = encryptionKeyLength;
    }

    public byte getBlockLength() {
        return blockLength;
    }

    public void setBlockLength(byte blockLength) {
        this.blockLength = blockLength;
    }

    public byte getFixedIvLength() {
        return fixedIvLength;
    }

    public void setFixedIvLength(byte fixedIvLength) {
        this.fixedIvLength = fixedIvLength;
    }

    public byte getRecordIvLength() {
        return recordIvLength;
    }

    public void setRecordIvLength(byte recordIvLength) {
        this.recordIvLength = recordIvLength;
    }

    public MACAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    public void setMacAlgorithm(MACAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    public byte getMacLength() {
        return macLength;
    }

    public void setMacLength(byte macLength) {
        this.macLength = macLength;
    }

    public byte getMacKeyLength() {
        return macKeyLength;
    }

    public void setMacKeyLength(byte macKeyLength) {
        this.macKeyLength = macKeyLength;
    }

    public CompressionMethod getCompressionMethod() {
        return compressionMethod;
    }

    public void setCompressionMethod(CompressionMethod compressionMethod) {
        this.compressionMethod = compressionMethod;
    }

    @Override
    public String toString() {
        return "SecurityParameters{" +
                "entity=" + entity +
                ", prfAlgorithm=" + prfAlgorithm +
                ", bulkCipherAlgorithm=" + bulkCipherAlgorithm +
                ", cipherType=" + cipherType +
                ", encryptionKeyLength=" + encryptionKeyLength +
                ", blockLength=" + blockLength +
                ", fixedIvLength=" + fixedIvLength +
                ", recordIvLength=" + recordIvLength +
                ", macAlgorithm=" + macAlgorithm +
                ", macLength=" + macLength +
                ", macKeyLength=" + macKeyLength +
                ", compressionMethod=" + compressionMethod +
                ", masterSecret=" + Arrays.toString(masterSecret) +
                ", clientRandom=" + Arrays.toString(clientRandom) +
                ", serverRandom=" + Arrays.toString(serverRandom) +
                '}';
    }
}
