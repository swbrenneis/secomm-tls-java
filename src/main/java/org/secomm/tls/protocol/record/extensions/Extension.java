package org.secomm.tls.protocol.record.extensions;

import java.io.IOException;
import java.io.OutputStream;

public interface Extension {

    public void encode(OutputStream out) throws IOException;

}
