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

package org.secomm.tls.test;

import org.junit.Test;
import org.secomm.tls.api.TlsClientContext;
import org.secomm.tls.api.TlsContext;
import org.secomm.tls.api.TlsPeer;
import org.secomm.tls.protocol.CipherSuites;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class APITest {

    @Test
    public void testConnect() throws Exception {

        TlsClientContext context = TlsContext.initializeClient(SecureRandom.getInstanceStrong());

        List<Short> cipherSuites = Stream.of(
                CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuites.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuites.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuites.TLS_DHE_PSK_WITH_AES_128_CCM
        ).collect(Collectors.toList());

        context.setCipherSuites(cipherSuites);
        context.setExtensions(new ArrayList<>());   // No extensions
        TlsPeer peer = context.connect("192.168.1.3", 9200);
    }
}
