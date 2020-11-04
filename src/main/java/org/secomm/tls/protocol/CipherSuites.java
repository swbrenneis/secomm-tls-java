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

package org.secomm.tls.protocol;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CipherSuites {
    
    public static final short TLS_NULL_WITH_NULL_NULL		= 0x0000;
    public static final short TLS_RSA_WITH_NULL_MD5		= 0x0001;
    public static final short TLS_RSA_WITH_NULL_SHA		= 0x0002;
    public static final short TLS_RSA_EXPORT_WITH_RC4_40_MD5		= 0x0003;
    public static final short TLS_RSA_WITH_RC4_128_MD5		= 0x0004;
    public static final short TLS_RSA_WITH_RC4_128_SHA		= 0x0005;
    public static final short TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5		= 0x0006;
    public static final short TLS_RSA_WITH_IDEA_CBC_SHA		= 0x0007;
    public static final short TLS_RSA_EXPORT_WITH_DES40_CBC_SHA		= 0x0008;
    public static final short TLS_RSA_WITH_DES_CBC_SHA		= 0x0009;
    public static final short TLS_RSA_WITH_3DES_EDE_CBC_SHA		= 0x000A;
    public static final short TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA		= 0x000B;
    public static final short TLS_DH_DSS_WITH_DES_CBC_SHA		= 0x000C;
    public static final short TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA		= 0x000D;
    public static final short TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA		= 0x000E;
    public static final short TLS_DH_RSA_WITH_DES_CBC_SHA		= 0x000F;
    public static final short TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA		= 0x0010;
    public static final short TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA		= 0x0011;
    public static final short TLS_DHE_DSS_WITH_DES_CBC_SHA		= 0x0012;
    public static final short TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA		= 0x0013;
    public static final short TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA		= 0x0014;
    public static final short TLS_DHE_RSA_WITH_DES_CBC_SHA		= 0x0015;
    public static final short TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA		= 0x0016;
    public static final short TLS_DH_anon_EXPORT_WITH_RC4_40_MD5		= 0x0017;
    public static final short TLS_DH_anon_WITH_RC4_128_MD5		= 0x0018;
    public static final short TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA		= 0x0019;
    public static final short TLS_DH_anon_WITH_DES_CBC_SHA		= 0x001A;
    public static final short TLS_DH_anon_WITH_3DES_EDE_CBC_SHA		= 0x001B;
    public static final short TLS_KRB5_WITH_DES_CBC_SHA		= 0x001E;
    public static final short TLS_KRB5_WITH_3DES_EDE_CBC_SHA		= 0x001F;
    public static final short TLS_KRB5_WITH_RC4_128_SHA		= 0x0020;
    public static final short TLS_KRB5_WITH_IDEA_CBC_SHA		= 0x0021;
    public static final short TLS_KRB5_WITH_DES_CBC_MD5		= 0x0022;
    public static final short TLS_KRB5_WITH_3DES_EDE_CBC_MD5		= 0x0023;
    public static final short TLS_KRB5_WITH_RC4_128_MD5		= 0x0024;
    public static final short TLS_KRB5_WITH_IDEA_CBC_MD5		= 0x0025;
    public static final short TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA		= 0x0026;
    public static final short TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA		= 0x0027;
    public static final short TLS_KRB5_EXPORT_WITH_RC4_40_SHA		= 0x0028;
    public static final short TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5		= 0x0029;
    public static final short TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5		= 0x002A;
    public static final short TLS_KRB5_EXPORT_WITH_RC4_40_MD5		= 0x002B;
    public static final short TLS_PSK_WITH_NULL_SHA		= 0x002C;
    public static final short TLS_DHE_PSK_WITH_NULL_SHA		= 0x002D;
    public static final short TLS_RSA_PSK_WITH_NULL_SHA		= 0x002E;
    public static final short TLS_RSA_WITH_AES_128_CBC_SHA		= 0x002F;
    public static final short TLS_DH_DSS_WITH_AES_128_CBC_SHA		= 0x0030;
    public static final short TLS_DH_RSA_WITH_AES_128_CBC_SHA		= 0x0031;
    public static final short TLS_DHE_DSS_WITH_AES_128_CBC_SHA		= 0x0032;
    public static final short TLS_DHE_RSA_WITH_AES_128_CBC_SHA		= 0x0033;
    public static final short TLS_DH_anon_WITH_AES_128_CBC_SHA		= 0x0034;
    public static final short TLS_RSA_WITH_AES_256_CBC_SHA		= 0x0035;
    public static final short TLS_DH_DSS_WITH_AES_256_CBC_SHA		= 0x0036;
    public static final short TLS_DH_RSA_WITH_AES_256_CBC_SHA		= 0x0037;
    public static final short TLS_DHE_DSS_WITH_AES_256_CBC_SHA		= 0x0038;
    public static final short TLS_DHE_RSA_WITH_AES_256_CBC_SHA		= 0x0039;
    public static final short TLS_DH_anon_WITH_AES_256_CBC_SHA		= 0x003A;
    public static final short TLS_RSA_WITH_NULL_SHA256		= 0x003B;
    public static final short TLS_RSA_WITH_AES_128_CBC_SHA256		= 0x003C;
    public static final short TLS_RSA_WITH_AES_256_CBC_SHA256		= 0x003D;
    public static final short TLS_DH_DSS_WITH_AES_128_CBC_SHA256		= 0x003E;
    public static final short TLS_DH_RSA_WITH_AES_128_CBC_SHA256		= 0x003F;
    public static final short TLS_DHE_DSS_WITH_AES_128_CBC_SHA256		= 0x0040;
    public static final short TLS_RSA_WITH_CAMELLIA_128_CBC_SHA		= 0x0041;
    public static final short TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA		= 0x0042;
    public static final short TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA		= 0x0043;
    public static final short TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA		= 0x0044;
    public static final short TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA		= 0x0045;
    public static final short TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA		= 0x0046;
    public static final short TLS_DHE_RSA_WITH_AES_128_CBC_SHA256		= 0x0067;
    public static final short TLS_DH_DSS_WITH_AES_256_CBC_SHA256		= 0x0068;
    public static final short TLS_DH_RSA_WITH_AES_256_CBC_SHA256		= 0x0069;
    public static final short TLS_DHE_DSS_WITH_AES_256_CBC_SHA256		= 0x006A;
    public static final short TLS_DHE_RSA_WITH_AES_256_CBC_SHA256		= 0x006B;
    public static final short TLS_DH_anon_WITH_AES_128_CBC_SHA256		= 0x006C;
    public static final short TLS_DH_anon_WITH_AES_256_CBC_SHA256		= 0x006D;
    public static final short TLS_RSA_WITH_CAMELLIA_256_CBC_SHA		= 0x0084;
    public static final short TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA		= 0x0085;
    public static final short TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA		= 0x0086;
    public static final short TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA		= 0x0087;
    public static final short TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA		= 0x0088;
    public static final short TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA		= 0x0089;
    public static final short TLS_PSK_WITH_RC4_128_SHA		= 0x008A;
    public static final short TLS_PSK_WITH_3DES_EDE_CBC_SHA		= 0x008B;
    public static final short TLS_PSK_WITH_AES_128_CBC_SHA		= 0x008C;
    public static final short TLS_PSK_WITH_AES_256_CBC_SHA		= 0x008D;
    public static final short TLS_DHE_PSK_WITH_RC4_128_SHA		= 0x008E;
    public static final short TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA		= 0x008F;
    public static final short TLS_DHE_PSK_WITH_AES_128_CBC_SHA		= 0x0090;
    public static final short TLS_DHE_PSK_WITH_AES_256_CBC_SHA		= 0x0091;
    public static final short TLS_RSA_PSK_WITH_RC4_128_SHA		= 0x0092;
    public static final short TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA		= 0x0093;
    public static final short TLS_RSA_PSK_WITH_AES_128_CBC_SHA		= 0x0094;
    public static final short TLS_RSA_PSK_WITH_AES_256_CBC_SHA		= 0x0095;
    public static final short TLS_RSA_WITH_SEED_CBC_SHA		= 0x0096;
    public static final short TLS_DH_DSS_WITH_SEED_CBC_SHA		= 0x0097;
    public static final short TLS_DH_RSA_WITH_SEED_CBC_SHA		= 0x0098;
    public static final short TLS_DHE_DSS_WITH_SEED_CBC_SHA		= 0x0099;
    public static final short TLS_DHE_RSA_WITH_SEED_CBC_SHA		= 0x009A;
    public static final short TLS_DH_anon_WITH_SEED_CBC_SHA		= 0x009B;
    public static final short TLS_RSA_WITH_AES_128_GCM_SHA256		= 0x009C;
    public static final short TLS_RSA_WITH_AES_256_GCM_SHA384		= 0x009D;
    public static final short TLS_DHE_RSA_WITH_AES_128_GCM_SHA256		= 0x009E;
    public static final short TLS_DHE_RSA_WITH_AES_256_GCM_SHA384		= 0x009F;
    public static final short TLS_DH_RSA_WITH_AES_128_GCM_SHA256		= 0x00A0;
    public static final short TLS_DH_RSA_WITH_AES_256_GCM_SHA384		= 0x00A1;
    public static final short TLS_DHE_DSS_WITH_AES_128_GCM_SHA256		= 0x00A2;
    public static final short TLS_DHE_DSS_WITH_AES_256_GCM_SHA384		= 0x00A3;
    public static final short TLS_DH_DSS_WITH_AES_128_GCM_SHA256		= 0x00A4;
    public static final short TLS_DH_DSS_WITH_AES_256_GCM_SHA384		= 0x00A5;
    public static final short TLS_DH_anon_WITH_AES_128_GCM_SHA256		= 0x00A6;
    public static final short TLS_DH_anon_WITH_AES_256_GCM_SHA384		= 0x00A7;
    public static final short TLS_PSK_WITH_AES_128_GCM_SHA256		= 0x00A8;
    public static final short TLS_PSK_WITH_AES_256_GCM_SHA384		= 0x00A9;
    public static final short TLS_DHE_PSK_WITH_AES_128_GCM_SHA256		= 0x00AA;
    public static final short TLS_DHE_PSK_WITH_AES_256_GCM_SHA384		= 0x00AB;
    public static final short TLS_RSA_PSK_WITH_AES_128_GCM_SHA256		= 0x00AC;
    public static final short TLS_RSA_PSK_WITH_AES_256_GCM_SHA384		= 0x00AD;
    public static final short TLS_PSK_WITH_AES_128_CBC_SHA256		= 0x00AE;
    public static final short TLS_PSK_WITH_AES_256_CBC_SHA384		= 0x00AF;
    public static final short TLS_PSK_WITH_NULL_SHA256		= 0x00B0;
    public static final short TLS_PSK_WITH_NULL_SHA384		= 0x00B1;
    public static final short TLS_DHE_PSK_WITH_AES_128_CBC_SHA256		= 0x00B2;
    public static final short TLS_DHE_PSK_WITH_AES_256_CBC_SHA384		= 0x00B3;
    public static final short TLS_DHE_PSK_WITH_NULL_SHA256		= 0x00B4;
    public static final short TLS_DHE_PSK_WITH_NULL_SHA384		= 0x00B5;
    public static final short TLS_RSA_PSK_WITH_AES_128_CBC_SHA256		= 0x00B6;
    public static final short TLS_RSA_PSK_WITH_AES_256_CBC_SHA384		= 0x00B7;
    public static final short TLS_RSA_PSK_WITH_NULL_SHA256		= 0x00B8;
    public static final short TLS_RSA_PSK_WITH_NULL_SHA384		= 0x00B9;
    public static final short TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256		= 0x00BA;
    public static final short TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256		= 0x00BB;
    public static final short TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256		= 0x00BC;
    public static final short TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256		= 0x00BD;
    public static final short TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256		= 0x00BE;
    public static final short TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256		= 0x00BF;
    public static final short TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256		= 0x00C0;
    public static final short TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256		= 0x00C1;
    public static final short TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256		= 0x00C2;
    public static final short TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256		= 0x00C3;
    public static final short TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256		= 0x00C4;
    public static final short TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256		= 0x00C5;
    public static final short TLS_SM4_GCM_SM3		= 0x00C6;
    public static final short TLS_SM4_CCM_SM3		= 0x00C7;
    public static final short TLS_EMPTY_RENEGOTIATION_INFO_SCSV		= 0x00FF;
    public static final short TLS_AES_128_GCM_SHA256		= 0x1301;
    public static final short TLS_AES_256_GCM_SHA384		= 0x1302;
    public static final short TLS_CHACHA20_POLY1305_SHA256		= 0x1303;
    public static final short TLS_AES_128_CCM_SHA256		= 0x1304;
    public static final short TLS_AES_128_CCM_8_SHA256		= 0x1305;
    public static final short TLS_FALLBACK_SCSV		= 0x5600;
    public static final short TLS_ECDH_ECDSA_WITH_NULL_SHA		=  (short) 0xC001;
    public static final short TLS_ECDH_ECDSA_WITH_RC4_128_SHA		=  (short) 0xC002;
    public static final short TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA		=  (short) 0xC003;
    public static final short TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA		=  (short) 0xC004;
    public static final short TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA		=  (short) 0xC005;
    public static final short TLS_ECDHE_ECDSA_WITH_NULL_SHA		=  (short) 0xC006;
    public static final short TLS_ECDHE_ECDSA_WITH_RC4_128_SHA		=  (short) 0xC007;
    public static final short TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA		=  (short) 0xC008;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA		=  (short) 0xC009;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA		=  (short) 0xC00A;
    public static final short TLS_ECDH_RSA_WITH_NULL_SHA		=  (short) 0xC00B;
    public static final short TLS_ECDH_RSA_WITH_RC4_128_SHA		=  (short) 0xC00C;
    public static final short TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA		=  (short) 0xC00D;
    public static final short TLS_ECDH_RSA_WITH_AES_128_CBC_SHA		=  (short) 0xC00E;
    public static final short TLS_ECDH_RSA_WITH_AES_256_CBC_SHA		=  (short) 0xC00F;
    public static final short TLS_ECDHE_RSA_WITH_NULL_SHA		=  (short) 0xC010;
    public static final short TLS_ECDHE_RSA_WITH_RC4_128_SHA		=  (short) 0xC011;
    public static final short TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA		=  (short) 0xC012;
    public static final short TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA		=  (short) 0xC013;
    public static final short TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA		=  (short) 0xC014;
    public static final short TLS_ECDH_anon_WITH_NULL_SHA		=  (short) 0xC015;
    public static final short TLS_ECDH_anon_WITH_RC4_128_SHA		=  (short) 0xC016;
    public static final short TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA		=  (short) 0xC017;
    public static final short TLS_ECDH_anon_WITH_AES_128_CBC_SHA		=  (short) 0xC018;
    public static final short TLS_ECDH_anon_WITH_AES_256_CBC_SHA		=  (short) 0xC019;
    public static final short TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA		=  (short) 0xC01A;
    public static final short TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA		=  (short) 0xC01B;
    public static final short TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA		=  (short) 0xC01C;
    public static final short TLS_SRP_SHA_WITH_AES_128_CBC_SHA		=  (short) 0xC01D;
    public static final short TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA		=  (short) 0xC01E;
    public static final short TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA		=  (short) 0xC01F;
    public static final short TLS_SRP_SHA_WITH_AES_256_CBC_SHA		=  (short) 0xC020;
    public static final short TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA		=  (short) 0xC021;
    public static final short TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA		=  (short) 0xC022;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256		=  (short) 0xC023;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384		=  (short) 0xC024;
    public static final short TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256		=  (short) 0xC025;
    public static final short TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384		=  (short) 0xC026;
    public static final short TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256		=  (short) 0xC027;
    public static final short TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384		=  (short) 0xC028;
    public static final short TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256		=  (short) 0xC029;
    public static final short TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384		=  (short) 0xC02A;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256		=  (short) 0xC02B;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384		=  (short) 0xC02C;
    public static final short TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256		=  (short) 0xC02D;
    public static final short TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384		=  (short) 0xC02E;
    public static final short TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256		=  (short) 0xC02F;
    public static final short TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384		=  (short) 0xC030;
    public static final short TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256		=  (short) 0xC031;
    public static final short TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384		=  (short) 0xC032;
    public static final short TLS_ECDHE_PSK_WITH_RC4_128_SHA		=  (short) 0xC033;
    public static final short TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA		=  (short) 0xC034;
    public static final short TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA		=  (short) 0xC035;
    public static final short TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA		=  (short) 0xC036;
    public static final short TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256		=  (short) 0xC037;
    public static final short TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384		=  (short) 0xC038;
    public static final short TLS_ECDHE_PSK_WITH_NULL_SHA		=  (short) 0xC039;
    public static final short TLS_ECDHE_PSK_WITH_NULL_SHA256		=  (short) 0xC03A;
    public static final short TLS_ECDHE_PSK_WITH_NULL_SHA384		=  (short) 0xC03B;
    public static final short TLS_RSA_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC03C;
    public static final short TLS_RSA_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC03D;
    public static final short TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC03E;
    public static final short TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC03F;
    public static final short TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC040;
    public static final short TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC041;
    public static final short TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC042;
    public static final short TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC043;
    public static final short TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC044;
    public static final short TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC045;
    public static final short TLS_DH_anon_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC046;
    public static final short TLS_DH_anon_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC047;
    public static final short TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC048;
    public static final short TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC049;
    public static final short TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC04A;
    public static final short TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC04B;
    public static final short TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC04C;
    public static final short TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC04D;
    public static final short TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC04E;
    public static final short TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC04F;
    public static final short TLS_RSA_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC050;
    public static final short TLS_RSA_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC051;
    public static final short TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC052;
    public static final short TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC053;
    public static final short TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC054;
    public static final short TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC055;
    public static final short TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC056;
    public static final short TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC057;
    public static final short TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC058;
    public static final short TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC059;
    public static final short TLS_DH_anon_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC05A;
    public static final short TLS_DH_anon_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC05B;
    public static final short TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC05C;
    public static final short TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC05D;
    public static final short TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC05E;
    public static final short TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC05F;
    public static final short TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC060;
    public static final short TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC061;
    public static final short TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC062;
    public static final short TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC063;
    public static final short TLS_PSK_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC064;
    public static final short TLS_PSK_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC065;
    public static final short TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC066;
    public static final short TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC067;
    public static final short TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC068;
    public static final short TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC069;
    public static final short TLS_PSK_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC06A;
    public static final short TLS_PSK_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC06B;
    public static final short TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC06C;
    public static final short TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC06D;
    public static final short TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256		=  (short) 0xC06E;
    public static final short TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384		=  (short) 0xC06F;
    public static final short TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256		=  (short) 0xC070;
    public static final short TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384		=  (short) 0xC071;
    public static final short TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256		=  (short) 0xC072;
    public static final short TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384		=  (short) 0xC073;
    public static final short TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256		=  (short) 0xC074;
    public static final short TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384		=  (short) 0xC075;
    public static final short TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256		=  (short) 0xC076;
    public static final short TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384		=  (short) 0xC077;
    public static final short TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256		=  (short) 0xC078;
    public static final short TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384		=  (short) 0xC079;
    public static final short TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC07A;
    public static final short TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC07B;
    public static final short TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC07C;
    public static final short TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC07D;
    public static final short TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC07E;
    public static final short TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC07F;
    public static final short TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC080;
    public static final short TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC081;
    public static final short TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC082;
    public static final short TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC083;
    public static final short TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC084;
    public static final short TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC085;
    public static final short TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC086;
    public static final short TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC087;
    public static final short TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC088;
    public static final short TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC089;
    public static final short TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC08A;
    public static final short TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC08B;
    public static final short TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC08C;
    public static final short TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC08D;
    public static final short TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC08E;
    public static final short TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC08F;
    public static final short TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC090;
    public static final short TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC091;
    public static final short TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256		=  (short) 0xC092;
    public static final short TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384		=  (short) 0xC093;
    public static final short TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256		=  (short) 0xC094;
    public static final short TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384		=  (short) 0xC095;
    public static final short TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256		=  (short) 0xC096;
    public static final short TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384		=  (short) 0xC097;
    public static final short TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256		=  (short) 0xC098;
    public static final short TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384		=  (short) 0xC099;
    public static final short TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256		=  (short) 0xC09A;
    public static final short TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384		=  (short) 0xC09B;
    public static final short TLS_RSA_WITH_AES_128_CCM		=  (short) 0xC09C;
    public static final short TLS_RSA_WITH_AES_256_CCM		=  (short) 0xC09D;
    public static final short TLS_DHE_RSA_WITH_AES_128_CCM		=  (short) 0xC09E;
    public static final short TLS_DHE_RSA_WITH_AES_256_CCM		=  (short) 0xC09F;
    public static final short TLS_RSA_WITH_AES_128_CCM_8		=  (short) 0xC0A0;
    public static final short TLS_RSA_WITH_AES_256_CCM_8		=  (short) 0xC0A1;
    public static final short TLS_DHE_RSA_WITH_AES_128_CCM_8		=  (short) 0xC0A2;
    public static final short TLS_DHE_RSA_WITH_AES_256_CCM_8		=  (short) 0xC0A3;
    public static final short TLS_PSK_WITH_AES_128_CCM		=  (short) 0xC0A4;
    public static final short TLS_PSK_WITH_AES_256_CCM		=  (short) 0xC0A5;
    public static final short TLS_DHE_PSK_WITH_AES_128_CCM		=  (short) 0xC0A6;
    public static final short TLS_DHE_PSK_WITH_AES_256_CCM		=  (short) 0xC0A7;
    public static final short TLS_PSK_WITH_AES_128_CCM_8		=  (short) 0xC0A8;
    public static final short TLS_PSK_WITH_AES_256_CCM_8		=  (short) 0xC0A9;
    public static final short TLS_PSK_DHE_WITH_AES_128_CCM_8		=  (short) 0xC0AA;
    public static final short TLS_PSK_DHE_WITH_AES_256_CCM_8		=  (short) 0xC0AB;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_128_CCM		=  (short) 0xC0AC;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_256_CCM		=  (short) 0xC0AD;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8		=  (short) 0xC0AE;
    public static final short TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8		=  (short) 0xC0AF;
    public static final short TLS_ECCPWD_WITH_AES_128_GCM_SHA256		=  (short) 0xC0B0;
    public static final short TLS_ECCPWD_WITH_AES_256_GCM_SHA384		=  (short) 0xC0B1;
    public static final short TLS_ECCPWD_WITH_AES_128_CCM_SHA256		=  (short) 0xC0B2;
    public static final short TLS_ECCPWD_WITH_AES_256_CCM_SHA384		=  (short) 0xC0B3;
    public static final short TLS_SHA256_SHA256		=  (short) 0xC0B4;
    public static final short TLS_SHA384_SHA384		=  (short) 0xC0B5;
    public static final short TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC		=  (short) 0xC100;
    public static final short TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC		=  (short) 0xC101;
    public static final short TLS_GOSTR341112_256_WITH_28147_CNT_IMIT		=  (short) 0xC102;
    public static final short TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L		=  (short) 0xC103;
    public static final short TLS_GOSTR341112_256_WITH_MAGMA_MGM_L		=  (short) 0xC104;
    public static final short TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S		=  (short) 0xC105;
    public static final short TLS_GOSTR341112_256_WITH_MAGMA_MGM_S		=  (short) 0xC106;
    public static final short TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256		=  (short) 0xCCA8;
    public static final short TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256		=  (short) 0xCCA9;
    public static final short TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256		=  (short) 0xCCAA;
    public static final short TLS_PSK_WITH_CHACHA20_POLY1305_SHA256		=  (short) 0xCCAB;
    public static final short TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256		=  (short) 0xCCAC;
    public static final short TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256		=  (short) 0xCCAD;
    public static final short TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256		=  (short) 0xCCAE;
    public static final short TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256		=  (short) 0xD001;
    public static final short TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384		=  (short) 0xD002;
    public static final short TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256		=  (short) 0xD003;
    public static final short TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256		=  (short) 0xD005;

    /**
     * This is the cipher suite that Firefox sends
     */
    public static final List<Short> defaultCipherSuites = Stream.of(
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA
    ).collect(Collectors.toList());

}
