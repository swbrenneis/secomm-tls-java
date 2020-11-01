package org.secomm.tls.crypto;

import java.security.InvalidParameterException;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Algorithms {

    public interface PrfBuilder <T extends PRFAlgorithm> {
        public T build();
    }

    public enum PrfAlgorithms { TLS_PRF_SHA256 }

    public static Map<PrfAlgorithms, PrfBuilder<?>> prfAlgorithms = Stream.of( new Object[][] {
            { PrfAlgorithms.TLS_PRF_SHA256 , new TlsPrfSha256.Builder() }
    }).collect(Collectors.toMap(e -> (PrfAlgorithms) e[0], e -> (PrfBuilder<?>) e[1]));

    public static <T extends PRFAlgorithm> T getPrfAlgorithm(PrfAlgorithms algorithm)
            throws InvalidParameterException {
        if (!prfAlgorithms.containsKey(algorithm)) {
            throw new InvalidParameterException("Unknown PRF algorithm identifier");
        }
        return (T) prfAlgorithms.get(algorithm).build();
    }

    public enum BulkCipherAlgorithm { NULL, RC4, TRIPLE_DES, AES }

    public enum CipherType { STREAM, BLOCK, AEAD }

    public enum MACAlgorithm{ NULL, HMAC_MD5, HMAC_SHA1, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512 }


}
