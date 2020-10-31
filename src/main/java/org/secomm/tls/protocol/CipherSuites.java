package org.secomm.tls.protocol;

public class CipherSuites {

    public static final byte[] TLS_NULL_WITH_NULL_NULL               = { 0x00,0x00 };
    public static final byte[] TLS_RSA_WITH_NULL_MD5                 = { 0x00,0x01 };
    public static final byte[] TLS_RSA_WITH_NULL_SHA                 = { 0x00,0x02 };
    public static final byte[] TLS_RSA_WITH_NULL_SHA256              = { 0x00,0x3B };
    public static final byte[] TLS_RSA_WITH_RC4_128_MD5              = { 0x00,0x04 };
    public static final byte[] TLS_RSA_WITH_RC4_128_SHA              = { 0x00,0x05 };
    public static final byte[] TLS_RSA_WITH_3DES_EDE_CBC_SHA         = { 0x00,0x0A };
    public static final byte[] TLS_RSA_WITH_AES_128_CBC_SHA          = { 0x00,0x2F };
    public static final byte[] TLS_RSA_WITH_AES_256_CBC_SHA          = { 0x00,0x35 };
    public static final byte[] TLS_RSA_WITH_AES_128_CBC_SHA256       = { 0x00,0x3C };
    public static final byte[] TLS_RSA_WITH_AES_256_CBC_SHA256       = { 0x00,0x3D };
    public static final byte[] TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x0D };
    public static final byte[] TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x10 };
    public static final byte[] TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x13 };
    public static final byte[] TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x16 };
    public static final byte[] TLS_DH_DSS_WITH_AES_128_CBC_SHA       = { 0x00,0x30 };
    public static final byte[] TLS_DH_RSA_WITH_AES_128_CBC_SHA       = { 0x00,0x31 };
    public static final byte[] TLS_DHE_DSS_WITH_AES_128_CBC_SHA      = { 0x00,0x32 };
    public static final byte[] TLS_DHE_RSA_WITH_AES_128_CBC_SHA      = { 0x00,0x33 };
    public static final byte[] TLS_DH_DSS_WITH_AES_256_CBC_SHA       = { 0x00,0x36 };
    public static final byte[] TLS_DH_RSA_WITH_AES_256_CBC_SHA       = { 0x00,0x37 };
    public static final byte[] TLS_DHE_DSS_WITH_AES_256_CBC_SHA      = { 0x00,0x38 };
    public static final byte[] TLS_DHE_RSA_WITH_AES_256_CBC_SHA      = { 0x00,0x39 };
    public static final byte[] TLS_DH_DSS_WITH_AES_128_CBC_SHA256    = { 0x00,0x3E };
    public static final byte[] TLS_DH_RSA_WITH_AES_128_CBC_SHA256    = { 0x00,0x3F };
    public static final byte[] TLS_DHE_DSS_WITH_AES_128_CBC_SHA256   = { 0x00,0x40 };
    public static final byte[] TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   = { 0x00,0x67 };
    public static final byte[] TLS_DH_DSS_WITH_AES_256_CBC_SHA256    = { 0x00,0x68 };
    public static final byte[] TLS_DH_RSA_WITH_AES_256_CBC_SHA256    = { 0x00,0x69 };
    public static final byte[] TLS_DHE_DSS_WITH_AES_256_CBC_SHA256   = { 0x00,0x6A };
    public static final byte[] TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   = { 0x00,0x6B };
    public static final byte[] TLS_DH_anon_WITH_RC4_128_MD5          = { 0x00,0x18 };
    public static final byte[] TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x1B };
    public static final byte[] TLS_DH_anon_WITH_AES_128_CBC_SHA      = { 0x00,0x34 };
    public static final byte[] TLS_DH_anon_WITH_AES_256_CBC_SHA      = { 0x00,0x3A };
    public static final byte[] TLS_DH_anon_WITH_AES_128_CBC_SHA256   = { 0x00,0x6C };
    public static final byte[] TLS_DH_anon_WITH_AES_256_CBC_SHA256   = { 0x00,0x6D };
}
