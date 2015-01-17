/*

stcompat.h -- SecureTransport compatibility header
Copyright (C) 2014,2015 Kyle J. McKay.  All rights reserved.

If this software is included as part of a build of
the cURL library, it may be used under the same license
terms as the cURL library.

Otherwise the GPLv2 license applies.

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

*/

#ifndef STCOMPAT_H
#define STCOMPAT_H

#include <TargetConditionals.h>
#include <AvailabilityMacros.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdarg.h>

#undef noErr
#define noErr 0 /* from MacTypes.h */
#undef errSecSuccess
#define errSecSuccess 0 /* from SecBase.h */
#undef unimpErr
#define unimpErr -4 /* from MacErrors.h */
#undef errSecUnimplemented
#define errSecUnimplemented -4 /* from SecBase.h */
#undef ioErr
#define ioErr -36 /* from MacErrors.h */
#undef paramErr
#define paramErr -50 /* from MacErrors.h */
#undef errSecParam
#define errSecParam -50 /* from SecBase.h */
#undef memFullErr
#define memFullErr -108 /* from MacErrors.h */
#undef errSecAllocate
#define errSecAllocate -108 /* from SecBase.h */

#ifndef TARGET_OS_EMBEDDED
#define TARGET_OS_EMBEDDED 0
#endif
#ifndef TARGET_OS_IPHONE
#define TARGET_OS_IPHONE 0
#endif

/* Some missing error defines */
#undef errSecSuccess
#define errSecSuccess                   0 /* alias for noErr 10.6+ */
#undef errSSLServerAuthCompleted
#define errSSLServerAuthCompleted       -9841 /* original name */
#undef errSSLClientAuthCompleted
#define errSSLClientAuthCompleted       -9841 /* added alias */
#undef errSSLPeerAuthCompleted
#define errSSLPeerAuthCompleted         -9841 /* new name */
#undef errSSLClientCertRequested
#define errSSLClientCertRequested       -9842
#undef errSecTrustSettingDeny
#define errSecTrustSettingDeny          -67654
#undef errSecNotTrusted
#define errSecNotTrusted                -67843

/* Custom error defines -- see Technical Q&A QA1499 */
#undef errSecPinnedKeyMismatch
#define errSecPinnedKeyMismatch 200001 /* user-defined error code */

/* Some missing session option defines */
#undef kSSLSessionOptionBreakOnServerAuth
#define kSSLSessionOptionBreakOnServerAuth 0
#undef kSSLSessionOptionBreakOnCertRequested
#define kSSLSessionOptionBreakOnCertRequested 1
#undef kSSLSessionOptionBreakOnClientAuth
#define kSSLSessionOptionBreakOnClientAuth 2
#undef kSSLSessionOptionFalseStart
#define kSSLSessionOptionFalseStart 3
#undef kSSLSessionOptionSendOneByteRecord
#define kSSLSessionOptionSendOneByteRecord 4
#undef kSSLSessionOptionAllowServerIdentityChange
#define kSSLSessionOptionAllowServerIdentityChange 5

/* The entire known cipher suite list */
#undef SSL_NULL_WITH_NULL_NULL
#define SSL_NULL_WITH_NULL_NULL                         0x0000
#undef TLS_NULL_WITH_NULL_NULL
#define TLS_NULL_WITH_NULL_NULL                         0x0000
#undef SSL_RSA_WITH_NULL_MD5
#define SSL_RSA_WITH_NULL_MD5                           0x0001
#undef TLS_RSA_WITH_NULL_MD5
#define TLS_RSA_WITH_NULL_MD5                           0x0001
#undef SSL_RSA_WITH_NULL_SHA
#define SSL_RSA_WITH_NULL_SHA                           0x0002
#undef TLS_RSA_WITH_NULL_SHA
#define TLS_RSA_WITH_NULL_SHA                           0x0002
#undef SSL_RSA_EXPORT_WITH_RC4_40_MD5
#define SSL_RSA_EXPORT_WITH_RC4_40_MD5                  0x0003
#undef SSL_RSA_WITH_RC4_128_MD5
#define SSL_RSA_WITH_RC4_128_MD5                        0x0004
#undef TLS_RSA_WITH_RC4_128_MD5
#define TLS_RSA_WITH_RC4_128_MD5                        0x0004
#undef SSL_RSA_WITH_RC4_128_SHA
#define SSL_RSA_WITH_RC4_128_SHA                        0x0005
#undef TLS_RSA_WITH_RC4_128_SHA
#define TLS_RSA_WITH_RC4_128_SHA                        0x0005
#undef SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5
#define SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5              0x0006
#undef SSL_RSA_WITH_IDEA_CBC_SHA
#define SSL_RSA_WITH_IDEA_CBC_SHA                       0x0007
#undef SSL_RSA_EXPORT_WITH_DES40_CBC_SHA
#define SSL_RSA_EXPORT_WITH_DES40_CBC_SHA               0x0008
#undef SSL_RSA_WITH_DES_CBC_SHA
#define SSL_RSA_WITH_DES_CBC_SHA                        0x0009
#undef SSL_RSA_WITH_3DES_EDE_CBC_SHA
#define SSL_RSA_WITH_3DES_EDE_CBC_SHA                   0x000A
#undef TLS_RSA_WITH_3DES_EDE_CBC_SHA
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA                   0x000A
#undef SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
#define SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA            0x000B
#undef SSL_DH_DSS_WITH_DES_CBC_SHA
#define SSL_DH_DSS_WITH_DES_CBC_SHA                     0x000C
#undef SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA
#define SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA                0x000D
#undef TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
#define TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA                0x000D
#undef SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
#define SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA            0x000E
#undef SSL_DH_RSA_WITH_DES_CBC_SHA
#define SSL_DH_RSA_WITH_DES_CBC_SHA                     0x000F
#undef SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA
#define SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA                0x0010
#undef TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
#define TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA                0x0010
#undef SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
#define SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA           0x0011
#undef SSL_DHE_DSS_WITH_DES_CBC_SHA
#define SSL_DHE_DSS_WITH_DES_CBC_SHA                    0x0012
#undef SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA
#define SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA               0x0013
#undef TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
#define TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA               0x0013
#undef SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
#define SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA           0x0014
#undef SSL_DHE_RSA_WITH_DES_CBC_SHA
#define SSL_DHE_RSA_WITH_DES_CBC_SHA                    0x0015
#undef SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
#define SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA               0x0016
#undef TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA               0x0016
#undef SSL_DH_anon_EXPORT_WITH_RC4_40_MD5
#define SSL_DH_anon_EXPORT_WITH_RC4_40_MD5              0x0017
#undef SSL_DH_anon_WITH_RC4_128_MD5
#define SSL_DH_anon_WITH_RC4_128_MD5                    0x0018
#undef TLS_DH_anon_WITH_RC4_128_MD5
#define TLS_DH_anon_WITH_RC4_128_MD5                    0x0018
#undef SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA
#define SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA           0x0019
#undef SSL_DH_anon_WITH_DES_CBC_SHA
#define SSL_DH_anon_WITH_DES_CBC_SHA                    0x001A
#undef SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
#define SSL_DH_anon_WITH_3DES_EDE_CBC_SHA               0x001B
#undef TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
#define TLS_DH_anon_WITH_3DES_EDE_CBC_SHA               0x001B
#undef SSL_FORTEZZA_DMS_WITH_NULL_SHA
#define SSL_FORTEZZA_DMS_WITH_NULL_SHA                  0x001C
#undef SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA
#define SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA          0x001D
#undef TLS_PSK_WITH_NULL_SHA
#define TLS_PSK_WITH_NULL_SHA                           0x002C
#undef TLS_DHE_PSK_WITH_NULL_SHA
#define TLS_DHE_PSK_WITH_NULL_SHA                       0x002D
#undef TLS_RSA_PSK_WITH_NULL_SHA
#define TLS_RSA_PSK_WITH_NULL_SHA                       0x002E
#undef TLS_RSA_WITH_AES_128_CBC_SHA
#define TLS_RSA_WITH_AES_128_CBC_SHA                    0x002F
#undef TLS_DH_DSS_WITH_AES_128_CBC_SHA
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA                 0x0030
#undef TLS_DH_RSA_WITH_AES_128_CBC_SHA
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA                 0x0031
#undef TLS_DHE_DSS_WITH_AES_128_CBC_SHA
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA                0x0032
#undef TLS_DHE_RSA_WITH_AES_128_CBC_SHA
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA                0x0033
#undef TLS_DH_anon_WITH_AES_128_CBC_SHA
#define TLS_DH_anon_WITH_AES_128_CBC_SHA                0x0034
#undef TLS_RSA_WITH_AES_256_CBC_SHA
#define TLS_RSA_WITH_AES_256_CBC_SHA                    0x0035
#undef TLS_DH_DSS_WITH_AES_256_CBC_SHA
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA                 0x0036
#undef TLS_DH_RSA_WITH_AES_256_CBC_SHA
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA                 0x0037
#undef TLS_DHE_DSS_WITH_AES_256_CBC_SHA
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA                0x0038
#undef TLS_DHE_RSA_WITH_AES_256_CBC_SHA
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA                0x0039
#undef TLS_DH_anon_WITH_AES_256_CBC_SHA
#define TLS_DH_anon_WITH_AES_256_CBC_SHA                0x003A
#undef TLS_RSA_WITH_NULL_SHA256
#define TLS_RSA_WITH_NULL_SHA256                        0x003B
#undef TLS_RSA_WITH_AES_128_CBC_SHA256
#define TLS_RSA_WITH_AES_128_CBC_SHA256                 0x003C
#undef TLS_RSA_WITH_AES_256_CBC_SHA256
#define TLS_RSA_WITH_AES_256_CBC_SHA256                 0x003D
#undef TLS_DH_DSS_WITH_AES_128_CBC_SHA256
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA256              0x003E
#undef TLS_DH_RSA_WITH_AES_128_CBC_SHA256
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA256              0x003F
#undef TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA256             0x0040
#undef TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256             0x0067
#undef TLS_DH_DSS_WITH_AES_256_CBC_SHA256
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA256              0x0068
#undef TLS_DH_RSA_WITH_AES_256_CBC_SHA256
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA256              0x0069
#undef TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA256             0x006A
#undef TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256             0x006B
#undef TLS_DH_anon_WITH_AES_128_CBC_SHA256
#define TLS_DH_anon_WITH_AES_128_CBC_SHA256             0x006C
#undef TLS_DH_anon_WITH_AES_256_CBC_SHA256
#define TLS_DH_anon_WITH_AES_256_CBC_SHA256             0x006D
#undef TLS_PSK_WITH_RC4_128_SHA
#define TLS_PSK_WITH_RC4_128_SHA                        0x008A
#undef TLS_PSK_WITH_3DES_EDE_CBC_SHA
#define TLS_PSK_WITH_3DES_EDE_CBC_SHA                   0x008B
#undef TLS_PSK_WITH_AES_128_CBC_SHA
#define TLS_PSK_WITH_AES_128_CBC_SHA                    0x008C
#undef TLS_PSK_WITH_AES_256_CBC_SHA
#define TLS_PSK_WITH_AES_256_CBC_SHA                    0x008D
#undef TLS_DHE_PSK_WITH_RC4_128_SHA
#define TLS_DHE_PSK_WITH_RC4_128_SHA                    0x008E
#undef TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
#define TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA               0x008F
#undef TLS_DHE_PSK_WITH_AES_128_CBC_SHA
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA                0x0090
#undef TLS_DHE_PSK_WITH_AES_256_CBC_SHA
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA                0x0091
#undef TLS_RSA_PSK_WITH_RC4_128_SHA
#define TLS_RSA_PSK_WITH_RC4_128_SHA                    0x0092
#undef TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
#define TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA               0x0093
#undef TLS_RSA_PSK_WITH_AES_128_CBC_SHA
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA                0x0094
#undef TLS_RSA_PSK_WITH_AES_256_CBC_SHA
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA                0x0095
#undef TLS_RSA_WITH_AES_128_GCM_SHA256
#define TLS_RSA_WITH_AES_128_GCM_SHA256                 0x009C
#undef TLS_RSA_WITH_AES_256_GCM_SHA384
#define TLS_RSA_WITH_AES_256_GCM_SHA384                 0x009D
#undef TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256             0x009E
#undef TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384             0x009F
#undef TLS_DH_RSA_WITH_AES_128_GCM_SHA256
#define TLS_DH_RSA_WITH_AES_128_GCM_SHA256              0x00A0
#undef TLS_DH_RSA_WITH_AES_256_GCM_SHA384
#define TLS_DH_RSA_WITH_AES_256_GCM_SHA384              0x00A1
#undef TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
#define TLS_DHE_DSS_WITH_AES_128_GCM_SHA256             0x00A2
#undef TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
#define TLS_DHE_DSS_WITH_AES_256_GCM_SHA384             0x00A3
#undef TLS_DH_DSS_WITH_AES_128_GCM_SHA256
#define TLS_DH_DSS_WITH_AES_128_GCM_SHA256              0x00A4
#undef TLS_DH_DSS_WITH_AES_256_GCM_SHA384
#define TLS_DH_DSS_WITH_AES_256_GCM_SHA384              0x00A5
#undef TLS_DH_anon_WITH_AES_128_GCM_SHA256
#define TLS_DH_anon_WITH_AES_128_GCM_SHA256             0x00A6
#undef TLS_DH_anon_WITH_AES_256_GCM_SHA384
#define TLS_DH_anon_WITH_AES_256_GCM_SHA384             0x00A7
#undef TLS_PSK_WITH_AES_128_GCM_SHA256
#define TLS_PSK_WITH_AES_128_GCM_SHA256                 0x00A8
#undef TLS_PSK_WITH_AES_256_GCM_SHA384
#define TLS_PSK_WITH_AES_256_GCM_SHA384                 0x00A9
#undef TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
#define TLS_DHE_PSK_WITH_AES_128_GCM_SHA256             0x00AA
#undef TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
#define TLS_DHE_PSK_WITH_AES_256_GCM_SHA384             0x00AB
#undef TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
#define TLS_RSA_PSK_WITH_AES_128_GCM_SHA256             0x00AC
#undef TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
#define TLS_RSA_PSK_WITH_AES_256_GCM_SHA384             0x00AD
#undef TLS_PSK_WITH_AES_128_CBC_SHA256
#define TLS_PSK_WITH_AES_128_CBC_SHA256                 0x00AE
#undef TLS_PSK_WITH_AES_256_CBC_SHA384
#define TLS_PSK_WITH_AES_256_CBC_SHA384                 0x00AF
#undef TLS_PSK_WITH_NULL_SHA256
#define TLS_PSK_WITH_NULL_SHA256                        0x00B0
#undef TLS_PSK_WITH_NULL_SHA384
#define TLS_PSK_WITH_NULL_SHA384                        0x00B1
#undef TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA256             0x00B2
#undef TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA384             0x00B3
#undef TLS_DHE_PSK_WITH_NULL_SHA256
#define TLS_DHE_PSK_WITH_NULL_SHA256                    0x00B4
#undef TLS_DHE_PSK_WITH_NULL_SHA384
#define TLS_DHE_PSK_WITH_NULL_SHA384                    0x00B5
#undef TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA256             0x00B6
#undef TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA384             0x00B7
#undef TLS_RSA_PSK_WITH_NULL_SHA256
#define TLS_RSA_PSK_WITH_NULL_SHA256                    0x00B8
#undef TLS_RSA_PSK_WITH_NULL_SHA384
#define TLS_RSA_PSK_WITH_NULL_SHA384                    0x00B9
#undef TLS_EMPTY_RENEGOTIATION_INFO_SCSV
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV               0x00FF
#undef TLS_ECDH_ECDSA_WITH_NULL_SHA
#define TLS_ECDH_ECDSA_WITH_NULL_SHA                    0xC001
#undef TLS_ECDH_ECDSA_WITH_RC4_128_SHA
#define TLS_ECDH_ECDSA_WITH_RC4_128_SHA                 0xC002
#undef TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
#define TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA            0xC003
#undef TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA             0xC004
#undef TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA             0xC005
#undef TLS_ECDHE_ECDSA_WITH_NULL_SHA
#define TLS_ECDHE_ECDSA_WITH_NULL_SHA                   0xC006
#undef TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
#define TLS_ECDHE_ECDSA_WITH_RC4_128_SHA                0xC007
#undef TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
#define TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA           0xC008
#undef TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA            0xC009
#undef TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA            0xC00A
#undef TLS_ECDH_RSA_WITH_NULL_SHA
#define TLS_ECDH_RSA_WITH_NULL_SHA                      0xC00B
#undef TLS_ECDH_RSA_WITH_RC4_128_SHA
#define TLS_ECDH_RSA_WITH_RC4_128_SHA                   0xC00C
#undef TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
#define TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA              0xC00D
#undef TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA               0xC00E
#undef TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA               0xC00F
#undef TLS_ECDHE_RSA_WITH_NULL_SHA
#define TLS_ECDHE_RSA_WITH_NULL_SHA                     0xC010
#undef TLS_ECDHE_RSA_WITH_RC4_128_SHA
#define TLS_ECDHE_RSA_WITH_RC4_128_SHA                  0xC011
#undef TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA             0xC012
#undef TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA              0xC013
#undef TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA              0xC014
#undef TLS_ECDH_anon_WITH_NULL_SHA
#define TLS_ECDH_anon_WITH_NULL_SHA                     0xC015
#undef TLS_ECDH_anon_WITH_RC4_128_SHA
#define TLS_ECDH_anon_WITH_RC4_128_SHA                  0xC016
#undef TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
#define TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA             0xC017
#undef TLS_ECDH_anon_WITH_AES_128_CBC_SHA
#define TLS_ECDH_anon_WITH_AES_128_CBC_SHA              0xC018
#undef TLS_ECDH_anon_WITH_AES_256_CBC_SHA
#define TLS_ECDH_anon_WITH_AES_256_CBC_SHA              0xC019
#undef TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256         0xC023
#undef TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384         0xC024
#undef TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256          0xC025
#undef TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384          0xC026
#undef TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256           0xC027
#undef TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384           0xC028
#undef TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256            0xC029
#undef TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384            0xC02A
#undef TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256         0xC02B
#undef TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384         0xC02C
#undef TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
#define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256          0xC02D
#undef TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
#define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384          0xC02E
#undef TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256           0xC02F
#undef TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384           0xC030
#undef TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
#define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256            0xC031
#undef TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
#define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384            0xC032
#undef SSL_RSA_WITH_RC2_CBC_MD5
#define SSL_RSA_WITH_RC2_CBC_MD5                        0xFF80
#undef SSL_RSA_WITH_IDEA_CBC_MD5
#define SSL_RSA_WITH_IDEA_CBC_MD5                       0xFF81
#undef SSL_RSA_WITH_DES_CBC_MD5
#define SSL_RSA_WITH_DES_CBC_MD5                        0xFF82
#undef SSL_RSA_WITH_3DES_EDE_CBC_MD5
#define SSL_RSA_WITH_3DES_EDE_CBC_MD5                   0xFF83
#undef SSL_NO_SUCH_CIPHERSUITE
#define SSL_NO_SUCH_CIPHERSUITE                         0xFFFF

#undef kTLSProtocol11
#define kTLSProtocol11 7
#undef kTLSProtocol12
#define kTLSProtocol12 8
#undef kDTLSProtocol1
#define kDTLSProtocol1 9

#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))

#include <Security/cssmapple.h>

#undef CSSM_CERT_STATUS_EXPIRED
#define CSSM_CERT_STATUS_EXPIRED                        0x00000001
#undef CSSM_CERT_STATUS_NOT_VALID_YET
#define CSSM_CERT_STATUS_NOT_VALID_YET                  0x00000002
#undef CSSM_CERT_STATUS_IS_IN_INPUT_CERTS
#define CSSM_CERT_STATUS_IS_IN_INPUT_CERTS              0x00000004
#undef CSSM_CERT_STATUS_IS_IN_ANCHORS
#define CSSM_CERT_STATUS_IS_IN_ANCHORS                  0x00000008
#undef CSSM_CERT_STATUS_IS_ROOT
#define CSSM_CERT_STATUS_IS_ROOT                        0x00000010
#undef CSSM_CERT_STATUS_IS_FROM_NET
#define CSSM_CERT_STATUS_IS_FROM_NET                    0x00000020
#undef CSSM_CERT_STATUS_TRUST_SETTINGS_FOUND_USER
#define CSSM_CERT_STATUS_TRUST_SETTINGS_FOUND_USER      0x00000040
#undef CSSM_CERT_STATUS_TRUST_SETTINGS_FOUND_ADMIN
#define CSSM_CERT_STATUS_TRUST_SETTINGS_FOUND_ADMIN     0x00000080
#undef CSSM_CERT_STATUS_TRUST_SETTINGS_FOUND_SYSTEM
#define CSSM_CERT_STATUS_TRUST_SETTINGS_FOUND_SYSTEM    0x00000100
#undef CSSM_CERT_STATUS_TRUST_SETTINGS_TRUST
#define CSSM_CERT_STATUS_TRUST_SETTINGS_TRUST           0x00000200
#undef CSSM_CERT_STATUS_TRUST_SETTINGS_DENY
#define CSSM_CERT_STATUS_TRUST_SETTINGS_DENY            0x00000400
#undef CSSM_CERT_STATUS_TRUST_SETTINGS_IGNORED_ERROR
#define CSSM_CERT_STATUS_TRUST_SETTINGS_IGNORED_ERROR   0x00000800

#undef kSSLServerSide
#define kSSLServerSide 0
#undef kSSLClientSide
#define kSSLClientSide 1

#undef kSSLStreamType
#define kSSLStreamType 0
#undef kSSLDatagramType
#define kSSLDatagramType 1

#undef SecItemImportExportKeyParameters
typedef struct {
  uint32_t version;
  SecKeyImportExportFlags flags;
  CFTypeRef passphrase;
  CFStringRef alertTitle;
  CFStringRef alertPrompt;
  SecAccessRef accessRef;
  CFArrayRef keyUsage;
  CFArrayRef keyAttributes;
} cSecItemImportExportKeyParameters;
#define SecItemImportExportKeyParameters cSecItemImportExportKeyParameters

typedef void (*errinfo_func_t)(void *, const char *, ...);

typedef struct {
  errinfo_func_t f;
  void *u;
} errinfo_t;

CFDataRef CFDataCreateWithContentsOfFile(CFAllocatorRef a, const char *f);
/* Never returns a 0-element array, returns NULL instead */
CFArrayRef CreateCertsArrayWithData(CFDataRef d, const errinfo_t *e);
Boolean CheckCertOkay(SecCertificateRef cert);
/* Never returns a 0-element array, returns NULL instead */
CFArrayRef CreatePubKeyArrayWithData(CFDataRef d, const errinfo_t *e);
Boolean CheckPubKeyOkay(CFDataRef pubkey);
/* caller must free() result unless NULL.  If s is NULL will return NULL.
 * if s is not NULL and release is true will CFRelease(s) before return */
char *CFStringCreateUTF8String(CFStringRef s, Boolean release);
/* Returns true if name is an IPv4 literal as defined in RFC 3986 section 3.2.2 */
Boolean IsIPv4Name(const void *name, size_t namelen);

OSStatus cSSLSetSessionOption(SSLContextRef cxt, int option, Boolean value);
SecCertificateRef cSecCertificateCreateWithData(CFAllocatorRef a, CFDataRef d);
CFDataRef cSecCertificateCopyData(SecCertificateRef c);
OSStatus cSecIdentityCreateWithCertificate(CFTypeRef k, SecCertificateRef c,
                                           SecIdentityRef *i);
SecIdentityRef cSecIdentityCreateWithCertificateAndKeyData(
  SecCertificateRef certificateRef, CFDataRef keydata, CFTypeRef pw,
  CFStringRef hint, void **kh);
void CopyCertValidity(SecCertificateRef cert, CFStringRef *nb, CFStringRef *na);
CFStringRef CopyCertSubject(SecCertificateRef cert);
CFStringRef CopyCertSubjectAltNamesString(SecCertificateRef cert);
CFStringRef CopyCertSubjectKeyId(SecCertificateRef cert);
CFStringRef CopyCertIssuer(SecCertificateRef cert);
CFStringRef CopyCertIssuerKeyId(SecCertificateRef cert);
OSStatus CopyIdentityWithLabel(const char *label, SecIdentityRef *out);
CFArrayRef CreateClientAuthWithCertificatesAndKeyData(CFArrayRef certs,
                                    CFDataRef keydata, CFTypeRef pw,
                                    CFStringRef hint, void **kh);
void DisposeIdentityKeychainHandle(void *);
OSStatus cSecItemImport(
  CFDataRef importedData, CFStringRef fileNameOrExtension,
  SecExternalFormat *inputFormat, SecExternalItemType *itemType,
  SecItemImportExportFlags flags, const SecItemImportExportKeyParameters *keyParams,
  SecKeychainRef importKeychain, CFArrayRef *outItems);
SSLContextRef cSSLCreateContext(CFAllocatorRef a, int ps, int ct);
void cSSLDisposeContext(SSLContextRef);
OSStatus cSSLSetTrustedRoots(SSLContextRef cxt, CFArrayRef rts, Boolean replace);
OSStatus cSSLCopyPeerTrust(SSLContextRef cxt, SecTrustRef *trust);
OSStatus cSecTrustSetAnchorCertificatesOnly(SecTrustRef cxt, Boolean anchorsOnly);
OSStatus cSSLCopyPeerCertificates(SSLContextRef cxt, CFArrayRef *certs);
OSStatus cSSLSetProtocolVersionMinMax(SSLContextRef cxt, int minVer, int maxVer);
OSStatus cSecTrustGetResult(
  SecTrustRef trust,
  SecTrustResultType *result,
  CFArrayRef *certChain,
  CSSM_TP_APPLE_EVIDENCE_INFO **statusChain);
/* If customRootsOrNull is not null, the root of the chain MUST be in
   customRootsOrNull.  If certFlags & 0x01 then all certs in the
   chain EXCEPT the root must come from the peer -- no magically appearing
   intermediate certs from who-knows-where are allowed.  The trust will
   automatically be evaluated if it has not already been.  If the chain is
   otherwise okay (would return errSecSuccess) but the trust result is other
   than unspecified or proceed then either errSecTrustSettingDeny (for
   kSecTrustResultDeny) or errSecNotTrusted (other codes) will be returned.
   Flags are CSSM_APPLE_TP_ACTION_FLAGS, pass 0 for normal behavior, only
   bits 0x1, 0x2 and 0x8 are checked in any case.  If peername is not NULL
   and not the empty string then it must match the leaf certificate.
   If pinnedKeySetOrNull is not NULL then the peer certificate's public key
   MUST be found in pinnedKeySetOrNull or errSecPinnedKeyMismatch will be
   returned.  This check is done last and only if no other error occurs.
   Setting certFlags & 0x02 causes ALL other checks to be skipped making
   it a pinned-key-check-only call.  If certFlags & 0x02 is set then
   pinnedKeySetOrNull MUST NOT be NULL.  If pinnedKeySetOrNull is not NULL
   it MUST have at least one element in it.  If certFlags & 0x04 is set
   then certificate chain validation errors are ignored (but host name
   matching will still be done if certFlags & 0x02 is NOT set).  If
   certFlags & 0x04 is set AND certFlags & 0x02 is NOT set then peername
   MUST NOT be NULL or the empty string.  */
OSStatus VerifyTrustChain(SecTrustRef trust, CFArrayRef customRootsOrNull,
                          unsigned certFlags, unsigned flags,
                          const char *peername, CFArrayRef pinnedKeySetOrNull);
/* returns true iff both certs are not NULL AND are DER byte-wise identical */
Boolean SecCertsEqual(SecCertificateRef c1, SecCertificateRef c2);
/* returns true iff at least one cert in a is SecCertsEqual to c */
Boolean SecCertInArray(SecCertificateRef c, CFArrayRef a);
/* returns true iff both items are not NULL AND are bite-wise identical */
Boolean BlobsEqual(CFDataRef b1, CFDataRef b2);
/* returns true iff at least one item in a is BlobsEqual to b */
Boolean BlobInArray(CFDataRef b, CFArrayRef a);

#elif TARGET_OS_EMBEDDED || TARGET_OS_IPHONE

#error iOS is not currently supported

#endif /* TARGET_OS_EMBEDDED || TARGET_OS_IPHONE */

#endif /* STCOMPAT_H */
