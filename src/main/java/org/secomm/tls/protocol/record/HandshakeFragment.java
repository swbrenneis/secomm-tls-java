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

package org.secomm.tls.protocol.record;

import org.secomm.tls.protocol.TlsConstants;
import org.secomm.tls.protocol.record.extensions.InvalidExtensionTypeException;
import org.secomm.tls.protocol.record.handshake.HandshakeMessageFactory;
import org.secomm.tls.protocol.record.handshake.InvalidHandshakeMessageType;
import org.secomm.tls.protocol.record.handshake.TlsHandshakeFragment;
import org.secomm.tls.protocol.record.handshake.TlsHandshakeMessage;
import org.secomm.tls.util.EncodingByteBuffer;

import java.io.IOException;

public class HandshakeFragment implements TlsHandshakeFragment {

    public static final class Builder implements FragmentFactory.FragmentBuilder<HandshakeFragment> {
        public HandshakeFragment build() throws InvalidHandshakeMessageType {
            return new HandshakeFragment();
        }
    }

    private byte messageType;

    /**
     * Encoded as a 24 bit integer.
     */
    private int handshakeLength;

    private TlsHandshakeMessage message;

    public HandshakeFragment(TlsHandshakeMessage handshake) {
        this.message = handshake;
        this.messageType = handshake.getHandshakeMessageType();
    }

    public HandshakeFragment() {
    }

    @Override
    public void decode(EncodingByteBuffer handshakeBuffer)
            throws InvalidHandshakeMessageType, IOException, InvalidExtensionTypeException {
        
        messageType = handshakeBuffer.get();
        message = HandshakeMessageFactory.getHandshake(messageType);
        int handshakeLength = handshakeBuffer.get24Bit();
        byte[] bytes = new byte[handshakeLength];
        handshakeBuffer.get(bytes);
        EncodingByteBuffer buffer = EncodingByteBuffer.wrap(bytes);
        message.decode(buffer);
    }

    @Override
    public byte[] encode() {
        byte[] handshakeBytes = message.encode();
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(handshakeBytes.length + 4);
        buffer.put(messageType);
        handshakeLength = handshakeBytes.length;
        buffer.put24Bit(handshakeLength);
        buffer.put(handshakeBytes);
        return buffer.toArray();
    }

    public <T extends TlsHandshakeMessage> T getHandshakeMessage() {
        return (T) message;
    }

    @Override
    public byte getFragmentType() {
        return TlsConstants.HANDSHAKE;
    }

    @Override
    public void setHandshakeMessage(TlsHandshakeMessage message) {
        this.messageType = message.getHandshakeMessageType();
        this.message = message;
    }
}
