package org.secomm.tls.crypto;

import org.secomm.tls.protocol.SecurityParameters;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class TlsCrypto {

    private final SecurityParameters securityParameters;

    private final SecureRandom secureRandom;

    public TlsCrypto(SecurityParameters securityParameters, SecureRandom secureRandom) {
        this.securityParameters = securityParameters;
        this.secureRandom = secureRandom;
    }


}
