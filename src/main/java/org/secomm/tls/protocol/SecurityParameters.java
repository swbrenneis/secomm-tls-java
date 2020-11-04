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

import org.secomm.tls.crypto.Algorithms;
import org.secomm.tls.crypto.PRFAlgorithm;

import java.util.Arrays;

public class SecurityParameters {

    public enum ConnectionEnd { CLIENT, SERVER }

    private final ConnectionEnd entity;

    private PRFAlgorithm prfAlgorithm;

    private Algorithms.BulkCipherAlgorithm bulkCipherAlgorithm;

    private Algorithms.CipherType cipherType;

    private int encryptionKeyLength;

    private int blockLength;

    private int fixedIvLength;

    private int recordIvLength;

    private Algorithms.MACAlgorithm macAlgorithm;

    private int macLength;

    private int macKeyLength;

    /**
     * The RFC defines two values. 0 and 255.
     */
    private int compressionMethod;

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

    public SecurityParameters(ConnectionEnd entity) {
        this.entity = entity;
    }

    public ConnectionEnd getEntity() {
        return entity;
    }

    public PRFAlgorithm getPrfAlgorithm() {
        return prfAlgorithm;
    }

    public void setPrfAlgorithm(PRFAlgorithm prfAlgorithm) {
        this.prfAlgorithm = prfAlgorithm;
    }

    public Algorithms.BulkCipherAlgorithm getBulkCipherAlgorithm() {
        return bulkCipherAlgorithm;
    }

    public void setBulkCipherAlgorithm(Algorithms.BulkCipherAlgorithm bulkCipherAlgorithm) {
        this.bulkCipherAlgorithm = bulkCipherAlgorithm;
    }

    public Algorithms.CipherType getCipherType() {
        return cipherType;
    }

    public void setCipherType(Algorithms.CipherType cipherType) {
        this.cipherType = cipherType;
    }

    public int getEncryptionKeyLength() {
        return encryptionKeyLength;
    }

    public void setEncryptionKeyLength(int encryptionKeyLength) {
        this.encryptionKeyLength = encryptionKeyLength;
    }

    public int getBlockLength() {
        return blockLength;
    }

    public void setBlockLength(int blockLength) {
        this.blockLength = blockLength;
    }

    public int getFixedIvLength() {
        return fixedIvLength;
    }

    public void setFixedIvLength(int fixedIvLength) {
        this.fixedIvLength = fixedIvLength;
    }

    public int getRecordIvLength() {
        return recordIvLength;
    }

    public void setRecordIvLength(int recordIvLength) {
        this.recordIvLength = recordIvLength;
    }

    public Algorithms.MACAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    public void setMacAlgorithm(Algorithms.MACAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    public int getMacLength() {
        return macLength;
    }

    public void setMacLength(int macLength) {
        this.macLength = macLength;
    }

    public int getMacKeyLength() {
        return macKeyLength;
    }

    public void setMacKeyLength(int macKeyLength) {
        this.macKeyLength = macKeyLength;
    }

    public int getCompressionMethod() {
        return compressionMethod;
    }

    public void setCompressionMethod(int compressionMethod) {
        this.compressionMethod = compressionMethod;
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
