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

package org.secomm.tls.protocol.record.extensions;

import org.secomm.tls.protocol.record.InvalidEncodingException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class SessionTicket extends AbstractExtension {

    public final static class Builder implements ExtensionFactory.ExtensionBuilder<SessionTicket> {
        @Override
        public SessionTicket build() {
            return new SessionTicket();
        }
    }

    private byte[] ticket;

    public SessionTicket() {
        super(Extensions.SESSION_TICKET);
        ticket = new byte[0];
    }

    public SessionTicket(byte[] ticket) {
        super(Extensions.SESSION_TICKET);
        this.ticket = ticket;
    }

    @Override
    protected void encodeExtensionData() throws IOException {

        ByteBuffer data = ByteBuffer.allocate(ticket.length + 2);
        data.putShort((short) ticket.length);
        if (ticket.length > 0) {
            data.put(ticket);
        }
        extensionData = data.array();
    }

    @Override
    protected void decodeExtensionData() {

        ByteBuffer data = ByteBuffer.wrap(extensionData);
        short ticketLength = data.getShort();
        if (ticketLength > 0) {
            ticket = new byte[ticketLength];
            data.get(ticket);
        }
    }

    @Override
    public String getText() throws InvalidEncodingException {
        String result = "Session Ticket\n";
        if (ticket.length == 0) {
            result += "\tEmpty\n";
        } else {
            result += "\t" + hexEncode(ticket) + "\n";
        }
        return result;
    }

    private String hexEncode(byte b) {

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
        return result;
    }

    private String hexEncode(byte[] bytes) {

        String result = "";
        for (byte b : bytes) {
            result += hexEncode(b);
        }
        return result;
    }

}
