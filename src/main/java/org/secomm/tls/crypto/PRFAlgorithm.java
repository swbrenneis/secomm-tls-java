package org.secomm.tls.crypto;

public interface PRFAlgorithm {

    public byte[] generateRandomBytes(String label, byte[] seed, int length);

}
