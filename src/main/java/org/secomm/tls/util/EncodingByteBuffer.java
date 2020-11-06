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

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.util.Arrays;

public class EncodingByteBuffer {

    private byte[] buffer;

    int position;

    int limit;

    boolean immutable;

    public static EncodingByteBuffer allocate(int size) {
        return new EncodingByteBuffer(size);
    }

    public static EncodingByteBuffer wrap(byte[] bytes) {
        return new EncodingByteBuffer(bytes);
    }

    private EncodingByteBuffer(int size) {
        buffer = new byte[size];
        limit = size;
        position = 0;
        immutable = false;
    }

    private EncodingByteBuffer(byte[] buffer) {
        this.buffer = Arrays.copyOf(buffer, buffer.length);
        limit = buffer.length;
        position = 0;
        immutable = true;
    }

    public byte get() {
        if (position > limit) {
            throw new BufferUnderflowException();
        }
        return buffer[position++];
    }

    public void get(byte[] out) {
        if (position + out.length > limit) {
            throw new BufferUnderflowException();
        }
        System.arraycopy(buffer, position, out, 0, out.length);
        position += out.length;
    }

    public short getShort() {
        if (position + 2 > limit) {
            throw new BufferUnderflowException();
        }
        // Network order (Big endian)
        int upper = buffer[position++];
        upper = (upper << 8) & 0xff00;
        int lower = buffer[position++];
        lower = lower & 0xff;
        return (short) (upper | lower);
    }

    public int get24Bit() {
        if (position + 3 > limit) {
            throw new BufferUnderflowException();
        }
        int upper = buffer[position++];
        upper = (upper << 16) & 0xff0000;
        int middle = buffer[position++];
        middle = (middle << 8) & 0xff00;
        int lower = buffer[position++];
        lower = lower & 0xff;
        return upper | middle | lower;
    }

    public void put(byte b) {
        if (position > limit) {
            throw new BufferOverflowException();
        }
        if (immutable) {
            throw new RuntimeException("Trying to modify an immutable buffer");
        }
        buffer[position++] = b;
    }

    public void put(byte[] bytes) {
        if (bytes.length + position > limit) {
            throw new BufferOverflowException();
        }
        if (immutable) {
            throw new RuntimeException("Trying to modify an immutable buffer");
        }
        System.arraycopy(bytes, 0, buffer, position, bytes.length);
        position += bytes.length;
    }

    public void putShort(short s) {
        if (position + 2 > limit) {
            throw new BufferOverflowException();
        }
        if (immutable) {
            throw new RuntimeException("Trying to modify an immutable buffer");
        }
        int upper = (s >> 8) & 0xff;
        int lower = s & 0xff;
        // Network order (Big endian)
        buffer[position++] = (byte) upper;
        buffer[position++] = (byte) lower;
    }

    public void put24Bit(int i24) {
        if (position + 3 > limit) {
            throw new BufferOverflowException();
        }
        if (immutable) {
            throw new RuntimeException("Trying to modify an immutable buffer");
        }
        buffer[position++] = (byte) ((i24 >> 16) & 0xff);
        buffer[position++] = (byte) ((i24 >> 8) & 0xff);
        buffer[position++] = (byte) (i24 & 0xff);
    }

    public byte[] toArray() {
        return Arrays.copyOf(buffer, position);
    }

    public boolean hasRemaining() {
        return position < limit;
    }
}
