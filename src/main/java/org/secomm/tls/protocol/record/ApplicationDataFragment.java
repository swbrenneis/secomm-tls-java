package org.secomm.tls.protocol.record;

public class ApplicationDataFragment implements TlsFragment {

    public static final class Builder implements ContentFactory.FragmentBuilder<ApplicationDataFragment> {
        public ApplicationDataFragment build(byte[] encoded) {
            return new ApplicationDataFragment(encoded);
        }
    }

    public ApplicationDataFragment(byte[] encoded) {
        
    }
    
    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
