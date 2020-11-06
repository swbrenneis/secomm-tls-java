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

import org.secomm.tls.protocol.record.InvalidEncodingException;
import org.secomm.tls.util.EncodingByteBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * RFC 6066 Section 8
 *
 *  struct {
 *      CertificateStatusType status_type;
 *      select (status_type) {
 *          case ocsp: OCSPStatusRequest;
 *      } request;
 *  } CertificateStatusRequest;
 *
 *  enum { ocsp(1), (255) } CertificateStatusType;
 *
 * struct {
 *  ResponderID responder_id_list<0..2^16-1>;
 *  Extensions  request_extensions;
 * } OCSPStatusRequest;
 *
 * opaque ResponderID<1..2^16-1>;
 * opaque Extensions<0..2^16-1>;
 *
 * For now, there is only one type of status request. If more are defined,
 * a factory will have to be created.
 */
public class CertificateStatusRequest extends AbstractTlsExtension {

    public static final class Builder implements ExtensionFactory.ExtensionBuilder<CertificateStatusRequest> {
        @Override
        public CertificateStatusRequest build() {
            return new CertificateStatusRequest();
        }
    }

    public interface CertificateStatus {
        void encode(EncodingByteBuffer buffer);
        void decode(EncodingByteBuffer data);
    }

    public static final byte OCSP_STATUS_REQUEST = 1;

    private byte statusType;

    private CertificateStatus request;

    /**
     * statusType will be zero and request will be null
     */
    public CertificateStatusRequest() {
        super(Extensions.CERTIFICATE_STATUS_REQUEST);
    }

    public CertificateStatusRequest(CertificateStatus request) {
        super(Extensions.CERTIFICATE_STATUS_REQUEST);
        this.request = request;
        statusType = OCSP_STATUS_REQUEST;
    }

    @Override
    protected void encodeExtensionData() {
        EncodingByteBuffer buffer = EncodingByteBuffer.allocate(1024);
        buffer.put(statusType);
        request.encode(buffer);
    }

    @Override
    protected void decodeExtensionData() {
        EncodingByteBuffer data = EncodingByteBuffer.wrap(extensionData);
        statusType = data.get();
        // Factory goes here when needed
        request = new OCSPStatusRequest();
        request.decode(data);
    }

    @Override
    public String getText() throws InvalidEncodingException {
        return null;
    }
}
