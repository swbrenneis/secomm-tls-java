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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
 * EXPRESSOR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMEN.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 */

package org.secomm.tls.test;

import org.junit.Assert;
import org.junit.Test;
import org.secomm.tls.protocol.record.ClientHello;
import org.secomm.tls.protocol.record.Handshake;
import org.secomm.tls.protocol.record.HandshakeFragment;
import org.secomm.tls.protocol.record.InvalidEncodingException;
import org.secomm.tls.protocol.record.RecordLayer;
import org.secomm.tls.protocol.record.TlsFragment;
import org.secomm.tls.protocol.record.TlsPlaintextRecord;
import org.secomm.tls.protocol.record.extensions.Extension;
import org.secomm.tls.protocol.record.extensions.ExtensionFactory;
import org.secomm.tls.util.NumberReaderWriter;

import javax.imageio.plugins.tiff.BaselineTIFFTagSet;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class ClientHelloTest {

    @Test
    public void testReceiveClientHello() throws Exception {

        ServerSocket serverSocket = new ServerSocket(8443);
        Socket clientSocket = serverSocket.accept();
        TlsPlaintextRecord record = new TlsPlaintextRecord();
        record.decode(new BufferedReader(new InputStreamReader(clientSocket.getInputStream())));
        serverSocket.close();

        HandshakeFragment handshakeFragment = record.getFragment();
        Handshake handshake = handshakeFragment.getHandshake();
        Assert.assertTrue(handshake instanceof ClientHello);
    }

    @Test
    public void analyzeReceivedClientHello() throws Exception {

/*
        ServerSocket serverSocket = new ServerSocket(8443);
        Socket clientSocket = serverSocket.accept();
        InputStream in = clientSocket.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        int type = reader.read();
        short version = NumberReaderWriter.readShort(reader);
        short length = NumberReaderWriter.readShort(reader);
        byte[] bytes = new byte[length];
        NumberReaderWriter.readBytes(bytes, reader);
        clientSocket.close();

        ByteBuffer encoded = ByteBuffer.allocate(length + 5);
        encoded.put((byte) type);
        encoded.putShort(version);
        encoded.putShort(length);
        encoded.put(bytes);
        System.out.println(hexEncode(encoded.array(), false));
        encoded.flip();
        analyzeClientHello(encoded);
*/
    }

    @Test
    public void testSendClientHello() throws Exception {

        SecureRandom random = SecureRandom.getInstanceStrong();
        RecordLayer recordLayer = new RecordLayer(RecordLayer.TLS_1_0, random);
        Socket socket = new Socket("www.example.com", 443);
        byte[] sessionId = new byte[0];
//        random.nextBytes(sessionId);
        recordLayer.sendClientHello(sessionId, socket.getOutputStream());
        TlsPlaintextRecord record = recordLayer.readPlaintextRecord(new BufferedReader(new InputStreamReader(socket.getInputStream())));
        TlsFragment fragment = record.getFragment();
    }

    @Test
    public void analyzeClientHello() throws Exception {

/*
        SecureRandom random = SecureRandom.getInstanceStrong();
        RecordLayer recordLayer = new RecordLayer(RecordLayer.TLS_1_0, random);
        byte[] sessionId = new byte[32];
        random.nextBytes(sessionId);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        recordLayer.sendClientHello(sessionId, out);
*/

        File dumpFile = new File("TestData/dump.txt");
        FileReader reader = new FileReader(dumpFile);
        char[] record = new char[(int) dumpFile.length()];
        reader.read(record);
        ByteBuffer encoded = ByteBuffer.wrap(hexDecode(record));
        analyzeClientHello(encoded);
    }

    private void analyzeClientHello(ByteBuffer encoded) throws Exception {

        System.out.println();
        System.out.println();
        byte b = encoded.get();
        Assert.assertEquals(0x16 , b);
        System.out.println("Handshake record:\t\t\t" + hexEncode(b, true));
        byte[] bytes = new byte[2];
        encoded.get(bytes);
        Assert.assertArrayEquals(new byte[] { 0x03, 0x01}, bytes);
        System.out.println("Version:\t\t\t\t\t" + hexEncode(bytes[0], true) + hexEncode(bytes[1], false));
        short length = encoded.getShort();
        System.out.println("Fragment size:\t\t\t\t" + length + " (" + hexEncode(length, true) + ")");
        b = encoded.get();
        Assert.assertEquals(0x01, b);
        System.out.println("Handshake type:\t\t\t\tClientHello (0x01)");
        int length24 = NumberReaderWriter.read24Bit(encoded);
        Assert.assertTrue(length24 < 16777216);
        System.out.println("ClientHello length:\t\t\t" + length24 + " (" + hexEncode24(length24, true) + ")");
        short version = encoded.getShort();
        Assert.assertEquals(0x0303, version);
        System.out.println("Version:\t\t\t\t\t" + hexEncode(version, true) + " (TLSv1.2)");
        bytes = new byte[32];
        encoded.get(bytes);
        System.out.println("Client random:\t\t\t\t" + hexEncode(bytes, false));
        b = encoded.get();
        System.out.println("Session ID length:\t\t\t" + b + " (" + hexEncode(b, true) + ")");
        if (b > 0) {
            bytes = new byte[b];
            encoded.get(bytes);
            System.out.println("Session ID:\t\t\t\t\t" + hexEncode(bytes, false));
        }
        length = encoded.getShort();
        System.out.println("Cipher suites length:\t\t" + length + " (" + hexEncode(length, true) +
                ") " + length/2 + " suites");
        short suite = encoded.getShort();
        System.out.print("Cipher suites:\t\t\t\t" + hexEncode(suite, true));
        for (int i = 0; i < (length / 2) -1; i++) {
            suite = encoded.getShort();
            System.out.print(", " + hexEncode(suite, true));
        }
        System.out.println();
        b = encoded.get();
        Assert.assertTrue(b < 2);
        System.out.println("Compression methods length:\t" + b + " (" + hexEncode(b, true) + ")");
        if (b > 0) {
            b = encoded.get();
            System.out.println("Compression method:\t\t\t" + b + " (" + hexEncode(b, true)  + ")");
        }
        length = encoded.getShort();
        System.out.println("Extensions length:\t\t\t" + length + " (" + hexEncode(length, true) + ")");
        if (length > 0) {
            byte[] extensionBytes = new byte[length];
            encoded.get(extensionBytes);
            ByteBuffer extensionBuffer = ByteBuffer.wrap(extensionBytes);
            while (extensionBuffer.hasRemaining()) {
                short extensionType = extensionBuffer.getShort();
                Extension extension = ExtensionFactory.getExtension(extensionType);
                extension.decode(extensionBuffer);
                System.out.println(extension.getText());
            }
        }
        System.out.println();
        System.out.println();

    }

    private String hexEncode(byte b, boolean prefix) {

        byte[] encoded = new byte[2];
        int hiNybble = (b >> 4) & 0x0f;
        int loNybble = b & 0x0f;
        if (hiNybble < 0x0a) {
            encoded[0] = (byte) (hiNybble + '0');
        } else {
            encoded[0] = (byte) ((hiNybble - 0x0a) + 'A');
        }
        if (loNybble < 0x0a) {
            encoded[1] = (byte) (loNybble + '0');
        } else {
            encoded[1] = (byte) ((loNybble - 0x0a) + 'A');
        }
        String result = new String(encoded, StandardCharsets.UTF_8);
        if (prefix) {
            result = "0x" + result;
        }
        return result;
    }

    private String hexEncode(byte[] bytes, boolean prefix) {

        String result = "";
        for (byte b : bytes) {
            result += hexEncode(b, prefix);
        }
        return result;
    }

    private String hexEncode(short s, boolean prefix) {

        byte[] bytes = new byte[2];
        bytes[0] = (byte) ((s >> 8) & 0xff);
        bytes[1] = (byte) (s & 0xff);
        String result = "";
        if (prefix) {
            result = "0x";
        }
        return result + hexEncode(bytes, false);
    }

    private String hexEncode24(int i, boolean prefix) {

        byte[] bytes = new byte[3];
        bytes[0] = (byte) ((i >> 16) & 0xff);
        bytes[1] = (byte) ((i >> 8) & 0xff);
        bytes[2] = (byte) (i & 0xff);
        String result = "";
        if (prefix) {
            result = "0x";
        }
        return result + hexEncode(bytes, false);
    }

    private byte[] hexDecode(char[] characters) throws InvalidEncodingException {

        int index = 0;
        byte[] bytes = new byte[characters.length];
        byte nybble = 0;
        for (char character : characters) {
            if (character >= '0' && character <= '9') {
                bytes[index++] = (byte) (character - '0');
            } else if (character >= 'A' && character <= 'F') {
                bytes[index++] = (byte) ((character - 'A') + 10);
            } else if (character >= 'a' && character <= 'f') {
                bytes[index++] = (byte) ((character - 'a') + 10);
            } else if (character == '\n' || character == ' ' || character == '\t') {
                // Ignore it.
                index++;
            } else {
                throw new InvalidEncodingException("Not a hex value");
            }
        }

        index = 0;
        boolean upper = true;
        byte[] result = new byte[characters.length / 2];
        int temp = 0;
        for (byte hex : bytes) {
            if (upper) {
                temp = hex & 0x0f;
                temp = temp << 4;
                upper = false;
            } else {
                temp |= hex & 0x0f;
                result[index++] = (byte) temp;
                upper = true;
            }
        }
        return result;
    }
}
