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

package org.secomm.tls.util;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class NumberReaderWriter {

    public static void writeShort(short s, OutputStream out) throws IOException {
        byte[] shortBytes = new byte[2];
        shortBytes[0] = (byte) ((s >> 8) & 0xff);
        shortBytes[1] = (byte) (s & 0xff);
        out.write(shortBytes);
    }

    public static byte[] write24Bit(int i) {
        byte[] int24 = new byte[3];
        int24[2] = (byte) (i & 0xff);
        int24[1] = (byte) ((i >> 8) & 0xff);
        int24[0] = (byte) ((i >> 16) & 0xff);
        return int24;
    }

    /**
     *
     * Read a 16 bit integer. Since bytes are signed, the byte to be
     * or'd needs to go through an integer and a mask.
     *
     * @param in
     * @return
     * @throws IOException
     */
    public static short readShort(ByteBuffer in) throws IOException {
        byte[] bytes = new byte[2];
        in.get(bytes);
        int result = 0;
        int temp = bytes[0];
        result = temp & 0xff;
        result = result << 8;
        temp = bytes[1];
        result |= temp & 0xff;
        return (short) result;
    }

    /**
     * Read a 24 bit integer. Since bytes are signed, the byte to be
     * or'd needs to go through an integer and a mask.
     *
     * @param in
     * @return
     * @throws IOException
     */
    public static int read24Bit(ByteBuffer in) throws IOException {

        byte[] bytes = new byte[3];
        in.get(bytes);
        int temp = bytes[0];
        int result = temp & 0xff;
        result = result << 8;
        temp = bytes[1];
        result |= temp & 0xff;
        result = result << 8;
        temp = bytes[2];
        result |= temp & 0xff;

        return result;
    }

    public static void readBytes(byte[] bytes, Reader in) throws IOException {
        char[] chars = new char[bytes.length];
        in.read(chars);
        int index = 0;
        for (char c : chars) {
            bytes[index++] = (byte) c;
        }
    }
}
