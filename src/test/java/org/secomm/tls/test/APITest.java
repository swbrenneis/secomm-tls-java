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

import org.junit.Assert;
import org.junit.Test;
import org.secomm.tls.api.TlsClientContext;
import org.secomm.tls.api.TlsContext;
import org.secomm.tls.api.TlsPeer;
import org.secomm.tls.protocol.CipherSuites;
import org.secomm.tls.protocol.record.HandshakeFragment;
import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.RecordLayerException;
import org.secomm.tls.protocol.record.TlsPlaintextRecord;
import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;
import org.secomm.tls.protocol.record.handshake.ClientKeyExchange;
import org.secomm.tls.protocol.record.handshake.TlsHandshakeFragment;
import org.secomm.tls.protocol.record.handshake.TlsHandshakeMessage;
import org.secomm.tls.util.EncodingByteBuffer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
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

        context.setCipherSuites(CipherSuites.defaultCipherSuites);
        context.setExtensions(new ArrayList<>());   // No extensions
        TlsPeer peer = context.connect("localhost", 5556);
//        TlsPeer peer = context.connect("www.example.com", 443);
//        TlsPeer peer = context.connect("206.74.33.52", 9100);
        Assert.assertNotNull(peer);
    }

    @Test
    public void encodeDecodeTest() throws Exception {

        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] fakeKey = new byte[128];
        random.nextBytes(fakeKey);
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange();
        clientKeyExchange.setClientPublicKey(fakeKey);
        TlsHandshakeFragment handshakeFragment = new HandshakeFragment();
        handshakeFragment.setHandshakeMessage(clientKeyExchange);
        TlsPlaintextRecord recordOut = new TlsPlaintextRecord(handshakeFragment.getFragmentType(),
                new RecordLayer.ProtocolVersion((byte) 0x03, (byte) 0x01));
        recordOut.setFragment(handshakeFragment);
        byte[] encoded = recordOut.encode();
        EncodingByteBuffer inBuffer = EncodingByteBuffer.wrap(encoded);

        ByteBuffer buffer = ByteBuffer.allocate(5);
        int length = fakeRead(inBuffer, buffer);
        buffer.flip();
        TlsPlaintextRecord record = new TlsPlaintextRecord(buffer.get(),
                new RecordLayer.ProtocolVersion(buffer.get(), buffer.get()));
        short fragmentLength = buffer.getShort();
        buffer = ByteBuffer.allocate(fragmentLength);
        length = fakeRead(inBuffer, buffer);
        buffer.flip();
        // We're going through all of this thrashing around because ByteBuffer
        // isn't really meant for what we're doing.
        byte[] recordBytes = new byte[length];
        buffer.get(recordBytes);
        record.decode(recordBytes);


    }

    private int fakeRead(EncodingByteBuffer in, ByteBuffer out) {
        byte[] inBytes = new byte[out.capacity()];
        in.get(inBytes);
        out.put(inBytes);
        return inBytes.length;
    }
}
