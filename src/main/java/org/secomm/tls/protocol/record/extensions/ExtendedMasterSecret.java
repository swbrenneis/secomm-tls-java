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

/**
 * RFC 7627 section 5.1
 */
public class ExtendedMasterSecret extends AbstractTlsExtension{

    public static final class Builder implements ExtensionFactory.ExtensionBuilder<ExtendedMasterSecret> {
        @Override
        public ExtendedMasterSecret build() {
            return new ExtendedMasterSecret();
        }
    }

    public ExtendedMasterSecret() {
        super(Extensions.EXTENDED_MASTER_SECRET);
    }

    @Override
    protected void encodeExtensionData() {
        extensionData = new byte[] { 0x00, 0x17, 0x00, 0x00 };
    }

    @Override
    protected void decodeExtensionData() {
        // Nothing to do here.
    }

    @Override
    public String getText() throws InvalidEncodingException {
        return "Extended Master Secret\n";
    }
}
