package org.secomm.tls.test;

import org.junit.Test;
import org.secomm.tls.protocol.record.AbstractHandshake;
import org.secomm.tls.protocol.record.HandshakeFragment;
import org.secomm.tls.protocol.record.HandshakeFragmentImpl;
import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.TlsPlaintextRecord;

import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

public class ClientHelloTest {

    @Test
    public void testReceiveClientHello() throws Exception {

        ServerSocket serverSocket = new ServerSocket(8443);
        Socket clientSocket = serverSocket.accept();
        InputStream stream = clientSocket.getInputStream();
        byte recordType = (byte) stream.read();
        byte majorVersion = (byte) stream.read();
        byte minorVersion = (byte) stream.read();
        byte[] lengthBytes = new byte[2];
        stream.read(lengthBytes);
        int contentLength = lengthBytes[0];
        contentLength = contentLength << 8;
        contentLength |= lengthBytes[1];
        byte[] content = new byte[contentLength];
        stream.read(content);
        stream.close();
        serverSocket.close();

        TlsPlaintextRecord record = new TlsPlaintextRecord(recordType, new RecordLayer.ProtocolVersion(majorVersion,minorVersion));
        record.setContent(content);
        HandshakeFragmentImpl handshakeFragment = record.getFragment();
        AbstractHandshake handshake = handshakeFragment.getHandshake();

        // No exceptions means test succeeded.
    }

    @Test
    public void testSendClientHello() throws Exception {

        RecordLayer recordLayer = new RecordLayer(new RecordLayer.ProtocolVersion((byte) 0x3, (byte) 0x3),
                SecureRandom.getInstanceStrong());
        Socket socket = new Socket("www.example.com", 443);
        recordLayer.sendClientHello(socket.getOutputStream());
        InputStream inputStream = socket.getInputStream();
        TlsPlaintextRecord record = recordLayer.readRecord(socket.getInputStream());
        HandshakeFragment handshakeFragment = record.getFragment();


    }
}
