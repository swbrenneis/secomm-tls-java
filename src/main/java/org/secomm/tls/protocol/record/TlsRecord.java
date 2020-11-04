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

package org.secomm.tls.protocol.record;

import org.secomm.tls.protocol.record.TlsFragment;

public abstract class TlsRecord {

    /**
     * Content types
     */
    public static final byte CHANGE_CIPHER_SPEC = 20;
    public static final byte ALERT = 21;
    public static final byte HANDSHAKE = 22;
    public static final byte APPLICATION_DATA = 23;

    protected byte contentType;

    protected RecordLayer.ProtocolVersion version;

    protected TlsFragment fragment;

    protected TlsRecord(byte contentType, RecordLayer.ProtocolVersion version) {
        this.contentType = contentType;
        this.version = version;
    }

    protected TlsRecord() {

    }

    public byte getContentType() {
        return contentType;
    }

    public RecordLayer.ProtocolVersion getVersion() {
        return version;
    }

    public <T extends TlsFragment> T getFragment() {
        return (T) fragment;
    }

    public void setFragment(TlsFragment fragment) {
        this.fragment = fragment;
    }
}
