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

package org.secomm.tls.protocol.record.extensions;

import org.secomm.tls.util.EncodingByteBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * RFC 6066 Section 8
 *
 * struct {
 *     ResponderID responder_id_list<0..2^16-1>;
 *     Extensions  request_extensions;
 * } OCSPStatusRequest;
 *
 * opaque ResponderID<1..2^16-1>;
 * opaque Extensions<0..2^16-1>;
 *
 *
 */
public class OCSPStatusRequest implements CertificateStatusRequest.CertificateStatus {

    private List<byte[]> responderIdList;

    private byte[] requestExtensions;

    public OCSPStatusRequest(List<byte[]> responderIdList, byte[] requestExtensions) {
        this.responderIdList = responderIdList;
        this.requestExtensions = requestExtensions;
    }

    public OCSPStatusRequest() {
        responderIdList = new ArrayList<>();
        requestExtensions = new byte[0];
    }

    @Override
    public void encode(EncodingByteBuffer buffer) {
        EncodingByteBuffer listEncoder = EncodingByteBuffer.allocate(1024);
        for (byte[] responderId : responderIdList) {
            listEncoder.putShort((short) responderId.length);
            listEncoder.put(responderId);
        }
        byte[] listBytes = listEncoder.toArray();
        buffer.putShort((short) listBytes.length);
        buffer.put(listBytes);
        buffer.putShort((short) requestExtensions.length);
        buffer.put(requestExtensions);
    }

    @Override
    public void decode(EncodingByteBuffer data) {
        short listLength = data.getShort();
        byte[] listBytes = new byte[listLength];
        data.get(listBytes);
        short requestLength = data.getShort();
        requestExtensions = new byte[requestLength];
        data.get(requestExtensions);

        // Decode the list
        responderIdList = new ArrayList<>();
        EncodingByteBuffer listDecoder = EncodingByteBuffer.wrap(listBytes);
        while (listDecoder.hasRemaining()) {
            short responderIdLength = listDecoder.getShort();
            byte[] responderId = new byte[responderIdLength];
            responderIdList.add(responderId);
        }
    }

}
