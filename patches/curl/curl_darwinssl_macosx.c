/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2014, Nick Zitzmann, <nickzman@gmail.com>.
 * Copyright (C) 2012 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 * MacOSX modifications copyright (C) 2014 Kyle J. McKay.  All rights reserved.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
 * Source file for all iOS and Mac OS X SecureTransport-specific code for the
 * TLS/SSL layer. No code but vtls.c should ever call or use these functions.
 */

#include "curl_setup.h"

#include "urldata.h" /* for the SessionHandle definition */

#ifdef USE_DARWINSSL

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>

/* The SecureTransport compatibility layer is separate */
#include "stcompat.h"

/* The Security framework has changed greatly between different OS X
   versions, and we will try to support as many of them as we can (back to
   Tiger) by using a compatibility layer.

   IMPORTANT: If TLS 1.1 and 1.2 support are important for you on OS X, then
   you must run the built project on 10.8 or later. */

#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1040
#error "The darwinssl macosx back-end requires Tiger or later."
#endif /* MAC_OS_X_VERSION_MIN_REQUIRED < 1040 */

#ifndef kCFCoreFoundationVersionNumber10_8
#define kCFCoreFoundationVersionNumber10_8 744.00
#endif
#ifndef kCFCoreFoundationVersionNumber10_8_3
#define kCFCoreFoundationVersionNumber10_8_3 744.18
#endif
#ifndef kCFCoreFoundationVersionNumber10_9
#define kCFCoreFoundationVersionNumber10_9 855.11
#endif

#elif TARGET_OS_EMBEDDED || TARGET_OS_IPHONE

#error iOS is not currently supported by this version of the darwinssl back-end

#else

#error the darwinssl macosx back-end requires Mac OS X

#endif /* (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)) */

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "connect.h"
#include "select.h"
#include "vtls.h"
#include "curl_darwinssl.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* The following two functions were ripped from Apple sample code,
 * with some modifications: */
static OSStatus SocketRead(SSLConnectionRef connection,
                           void *data,          /* owned by
                                                 * caller, data
                                                 * RETURNED */
                           size_t *dataLength)  /* IN/OUT */
{
  size_t bytesToGo = *dataLength;
  size_t initLen = bytesToGo;
  UInt8 *currData = (UInt8 *)data;
  /*int sock = *(int *)connection;*/
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)connection;
  int sock = connssl->ssl_sockfd;
  OSStatus rtn = noErr;
  size_t bytesRead;
  ssize_t rrtn;
  int theErr;

  *dataLength = 0;

  for(;;) {
    bytesRead = 0;
    rrtn = read(sock, currData, bytesToGo);
    if(rrtn <= 0) {
      /* this is guesswork... */
      theErr = errno;
      if(rrtn == 0) { /* EOF = server hung up */
        /* the framework will turn this into errSSLClosedNoNotify */
        rtn = errSSLClosedGraceful;
      }
      else /* do the switch */
        switch(theErr) {
          case ENOENT:
            /* connection closed */
            rtn = errSSLClosedGraceful;
            break;
          case ECONNRESET:
            rtn = errSSLClosedAbort;
            break;
          case EAGAIN:
            rtn = errSSLWouldBlock;
            connssl->ssl_direction = false;
            break;
          default:
            rtn = ioErr;
            break;
        }
      break;
    }
    else {
      bytesRead = rrtn;
    }
    bytesToGo -= bytesRead;
    currData  += bytesRead;

    if(bytesToGo == 0) {
      /* filled buffer with incoming data, done */
      break;
    }
  }
  *dataLength = initLen - bytesToGo;

  return rtn;
}

static OSStatus SocketWrite(SSLConnectionRef connection,
                            const void *data,
                            size_t *dataLength)  /* IN/OUT */
{
  size_t bytesSent = 0;
  /*int sock = *(int *)connection;*/
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)connection;
  int sock = connssl->ssl_sockfd;
  ssize_t length;
  size_t dataLen = *dataLength;
  const UInt8 *dataPtr = (UInt8 *)data;
  OSStatus ortn;
  int theErr;

  *dataLength = 0;

  do {
    length = write(sock,
                   (char*)dataPtr + bytesSent,
                   dataLen - bytesSent);
  } while((length > 0) &&
           ( (bytesSent += length) < dataLen) );

  if(length <= 0) {
    theErr = errno;
    if(theErr == EAGAIN) {
      ortn = errSSLWouldBlock;
      connssl->ssl_direction = true;
    }
    else {
      ortn = ioErr;
    }
  }
  else {
    ortn = noErr;
  }
  *dataLength = bytesSent;
  return ortn;
}

CF_INLINE const char *SSLCipherNameForNumber(SSLCipherSuite cipher) {
  switch (cipher) {
#define CIPHER(x) case x: return #x
    /* SSL version 3.0 */
    CIPHER(SSL_RSA_WITH_NULL_MD5);
    CIPHER(SSL_RSA_WITH_NULL_SHA);
    CIPHER(SSL_RSA_EXPORT_WITH_RC4_40_MD5);
    CIPHER(SSL_RSA_WITH_RC4_128_MD5);
    CIPHER(SSL_RSA_WITH_RC4_128_SHA);
    CIPHER(SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
    CIPHER(SSL_RSA_WITH_IDEA_CBC_SHA);
    CIPHER(SSL_RSA_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_RSA_WITH_DES_CBC_SHA);
    CIPHER(SSL_RSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DH_DSS_WITH_DES_CBC_SHA);
    CIPHER(SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DH_RSA_WITH_DES_CBC_SHA);
    CIPHER(SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DHE_DSS_WITH_DES_CBC_SHA);
    CIPHER(SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DHE_RSA_WITH_DES_CBC_SHA);
    CIPHER(SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DH_anon_EXPORT_WITH_RC4_40_MD5);
    CIPHER(SSL_DH_anon_WITH_RC4_128_MD5);
    CIPHER(SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DH_anon_WITH_DES_CBC_SHA);
    CIPHER(SSL_DH_anon_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_FORTEZZA_DMS_WITH_NULL_SHA);
    CIPHER(SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA);
    /* TLS 1.0 with AES (RFC 3268)
       (Apparently these are used in SSLv3 implementations as well.) */
    CIPHER(TLS_RSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DH_DSS_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DH_RSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DH_anon_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_RSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DH_DSS_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DH_RSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DH_anon_WITH_AES_256_CBC_SHA);
    /* SSL version 2.0 */
    CIPHER(SSL_RSA_WITH_RC2_CBC_MD5);
    CIPHER(SSL_RSA_WITH_IDEA_CBC_MD5);
    CIPHER(SSL_RSA_WITH_DES_CBC_MD5);
    CIPHER(SSL_RSA_WITH_3DES_EDE_CBC_MD5);
#undef CIPHER
  }
  return "SSL_NULL_WITH_NULL_NULL";
}

CF_INLINE const char *TLSCipherNameForNumber(SSLCipherSuite cipher) {
  switch(cipher) {
#define CIPHER(x) case x: return #x
    CIPHER(TLS_RSA_WITH_NULL_MD5);
    CIPHER(TLS_RSA_WITH_NULL_SHA);
    CIPHER(SSL_RSA_EXPORT_WITH_RC4_40_MD5);
    CIPHER(TLS_RSA_WITH_RC4_128_MD5);
    CIPHER(TLS_RSA_WITH_RC4_128_SHA);
    CIPHER(SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
    CIPHER(SSL_RSA_WITH_IDEA_CBC_SHA);
    CIPHER(SSL_RSA_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_RSA_WITH_DES_CBC_SHA);
    CIPHER(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DH_DSS_WITH_DES_CBC_SHA);
    CIPHER(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DH_RSA_WITH_DES_CBC_SHA);
    CIPHER(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DHE_DSS_WITH_DES_CBC_SHA);
    CIPHER(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DHE_RSA_WITH_DES_CBC_SHA);
    CIPHER(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_DH_anon_EXPORT_WITH_RC4_40_MD5);
    CIPHER(TLS_DH_anon_WITH_RC4_128_MD5);
    CIPHER(SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA);
    CIPHER(SSL_DH_anon_WITH_DES_CBC_SHA);
    CIPHER(TLS_DH_anon_WITH_3DES_EDE_CBC_SHA);
    CIPHER(SSL_FORTEZZA_DMS_WITH_NULL_SHA);
    CIPHER(SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA);
    CIPHER(TLS_PSK_WITH_NULL_SHA);
    CIPHER(TLS_DHE_PSK_WITH_NULL_SHA);
    CIPHER(TLS_RSA_PSK_WITH_NULL_SHA);
    CIPHER(TLS_RSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DH_DSS_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DH_RSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DH_anon_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_RSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DH_DSS_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DH_RSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DH_anon_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_RSA_WITH_NULL_SHA256);
    CIPHER(TLS_RSA_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_RSA_WITH_AES_256_CBC_SHA256);
    CIPHER(TLS_DH_DSS_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_DH_RSA_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_DH_DSS_WITH_AES_256_CBC_SHA256);
    CIPHER(TLS_DH_RSA_WITH_AES_256_CBC_SHA256);
    CIPHER(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
    CIPHER(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
    CIPHER(TLS_DH_anon_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_DH_anon_WITH_AES_256_CBC_SHA256);
    CIPHER(TLS_PSK_WITH_RC4_128_SHA);
    CIPHER(TLS_PSK_WITH_3DES_EDE_CBC_SHA);
    CIPHER(TLS_PSK_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_PSK_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_DHE_PSK_WITH_RC4_128_SHA);
    CIPHER(TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA);
    CIPHER(TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_DHE_PSK_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_RSA_PSK_WITH_RC4_128_SHA);
    CIPHER(TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA);
    CIPHER(TLS_RSA_PSK_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_RSA_PSK_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_RSA_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_RSA_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_DH_RSA_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_DH_RSA_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_DH_DSS_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_DH_DSS_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_DH_anon_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_DH_anon_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_PSK_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_PSK_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_DHE_PSK_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_DHE_PSK_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_RSA_PSK_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_RSA_PSK_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_PSK_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_PSK_WITH_AES_256_CBC_SHA384);
    CIPHER(TLS_PSK_WITH_NULL_SHA256);
    CIPHER(TLS_PSK_WITH_NULL_SHA384);
    CIPHER(TLS_DHE_PSK_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_DHE_PSK_WITH_AES_256_CBC_SHA384);
    CIPHER(TLS_DHE_PSK_WITH_NULL_SHA256);
    CIPHER(TLS_DHE_PSK_WITH_NULL_SHA384);
    CIPHER(TLS_RSA_PSK_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_RSA_PSK_WITH_AES_256_CBC_SHA384);
    CIPHER(TLS_RSA_PSK_WITH_NULL_SHA256);
    CIPHER(TLS_RSA_PSK_WITH_NULL_SHA384);
    CIPHER(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    CIPHER(TLS_ECDH_ECDSA_WITH_NULL_SHA);
    CIPHER(TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
    CIPHER(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_ECDHE_ECDSA_WITH_NULL_SHA);
    CIPHER(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
    CIPHER(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_ECDH_RSA_WITH_NULL_SHA);
    CIPHER(TLS_ECDH_RSA_WITH_RC4_128_SHA);
    CIPHER(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_ECDHE_RSA_WITH_NULL_SHA);
    CIPHER(TLS_ECDHE_RSA_WITH_RC4_128_SHA);
    CIPHER(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
    CIPHER(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_ECDH_anon_WITH_NULL_SHA);
    CIPHER(TLS_ECDH_anon_WITH_RC4_128_SHA);
    CIPHER(TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
    CIPHER(TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
    CIPHER(TLS_ECDH_anon_WITH_AES_256_CBC_SHA);
    CIPHER(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
    CIPHER(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384);
    CIPHER(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
    CIPHER(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
    CIPHER(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384);
    CIPHER(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    CIPHER(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
    CIPHER(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384);
    CIPHER(SSL_RSA_WITH_RC2_CBC_MD5);
    CIPHER(SSL_RSA_WITH_IDEA_CBC_MD5);
    CIPHER(SSL_RSA_WITH_DES_CBC_MD5);
    CIPHER(SSL_RSA_WITH_3DES_EDE_CBC_MD5);
#undef CIPHER
  }
  return "TLS_NULL_WITH_NULL_NULL";
}

/* This code was borrowed from nss.c, with some modifications:
 * Determine whether the nickname passed in is a filename that needs to
 * be loaded as a PEM or a regular NSS nickname.
 *
 * returns 1 for a file
 * returns 0 for not a file
 */
CF_INLINE bool is_file(const char *filename)
{
  struct_stat st;

  if(filename == NULL)
    return false;

  if(stat(filename, &st) == 0)
    return S_ISREG(st.st_mode);
  return false;
}

static CURLcode darwinssl_connect_step1(struct connectdata *conn,
                                        int sockindex)
{
  struct SessionHandle *data = conn->data;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
#ifdef ENABLE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif /* ENABLE_IPV6 */
  size_t all_ciphers_count = 0UL, allowed_ciphers_count = 0UL, i;
  SSLCipherSuite *all_ciphers = NULL, *allowed_ciphers = NULL;
  char *ssl_sessionid;
  size_t ssl_sessionid_len;
  OSStatus err = noErr;

  if(connssl->kh) {
    DisposeIdentityKeychainHandle(connssl->kh);
    connssl->kh = NULL;
  }
  if(connssl->ssl_ctx)
    cSSLDisposeContext(connssl->ssl_ctx);
  connssl->ssl_ctx = cSSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
  if(!connssl->ssl_ctx) {
    failf(data, "SSL: couldn't create a context!");
    return CURLE_OUT_OF_MEMORY;
  }
  connssl->ssl_write_buffered_length = 0UL; /* reset buffered write length */

  /* check to see if we've been told to use an explicit SSL/TLS version */
  switch(data->set.ssl.version) {
    case CURL_SSLVERSION_DEFAULT: default:
      (void)cSSLSetProtocolVersionMinMax(connssl->ssl_ctx, kSSLProtocol3,
                                                           kTLSProtocol12);
      break;
    case CURL_SSLVERSION_TLSv1:
      (void)cSSLSetProtocolVersionMinMax(connssl->ssl_ctx, kTLSProtocol1,
                                                           kTLSProtocol12);
      break;
    case CURL_SSLVERSION_TLSv1_0:
      (void)cSSLSetProtocolVersionMinMax(connssl->ssl_ctx, kTLSProtocol1,
                                                           kTLSProtocol1);
      break;
    case CURL_SSLVERSION_TLSv1_1:
      err = cSSLSetProtocolVersionMinMax(connssl->ssl_ctx, kTLSProtocol11,
                                                           kTLSProtocol11);
      if(err != noErr) {
        failf(data, "Your version of the OS does not support TLSv1.1");
        return CURLE_SSL_CONNECT_ERROR;
      }
      break;
    case CURL_SSLVERSION_TLSv1_2:
      err = cSSLSetProtocolVersionMinMax(connssl->ssl_ctx, kTLSProtocol12,
                                                           kTLSProtocol12);
      if(err != noErr) {
        failf(data, "Your version of the OS does not support TLSv1.2");
        return CURLE_SSL_CONNECT_ERROR;
      }
      break;
    case CURL_SSLVERSION_SSLv3:
      (void)cSSLSetProtocolVersionMinMax(connssl->ssl_ctx, kSSLProtocol3,
                                                           kSSLProtocol3);
      break;
    case CURL_SSLVERSION_SSLv2:
      err = cSSLSetProtocolVersionMinMax(connssl->ssl_ctx, kSSLProtocol2,
                                                           kSSLProtocol2);
      if(err != noErr) {
        failf(data, "Your version of the OS does not support SSLv2");
        return CURLE_SSL_CONNECT_ERROR;
      }
      break;
  }

  if(data->set.str[STRING_CERT]) {
    CFArrayRef certs = NULL;
    bool is_cert_file = is_file(data->set.str[STRING_CERT]);

    /* User wants to authenticate with a client cert. Look for it:
       If we detect that this is a file on disk, then let's load it.
       Otherwise, assume that the user wants to use an identity loaded
       from the Keychain. */
    if(is_cert_file) {
      errinfo_t e;
      CFDataRef certdata;
      CFDataRef keypw = NULL;
      CFArrayRef clientauth;
      e.f = (errinfo_func_t)failf;
      e.u = data;
      if(data->set.str[STRING_CERT_TYPE]) {
        if(strcmp(data->set.str[STRING_CERT_TYPE], "DER") &&
           strcmp(data->set.str[STRING_CERT_TYPE], "PEM")) {
          failf(data, "not supported file type '%s' for certificate\n",
                      data->set.str[STRING_CERT_TYPE]);
          return CURLE_SSL_CERTPROBLEM;
        }
      }
      certdata = CFDataCreateWithContentsOfFile(NULL,
                                                data->set.str[STRING_CERT]);
      if(!certdata) {
        failf(data, "unable to read certificate data file '%s'\n",
                    data->set.str[STRING_CERT]);
        return CURLE_SSL_CERTPROBLEM;
      }
      certs = CreateCertsArrayWithData(certdata, &e);
      if(!certs) {
        CFRelease(certdata);
        failf(data, "unable to load certificate data file '%s'\n",
                    data->set.str[STRING_CERT]);
        return CURLE_SSL_CERTPROBLEM;
      }
      if(data->set.str[STRING_KEY]) {
        CFRelease(certdata);
        certdata = CFDataCreateWithContentsOfFile(NULL,
                                                  data->set.str[STRING_KEY]);
        if(!certdata) {
          CFRelease(certs);
          failf(data, "unable to read certificate key file '%s'\n",
                      data->set.str[STRING_KEY]);
          return CURLE_SSL_CERTPROBLEM;
        }
      }
      if(data->set.str[STRING_KEY_PASSWD]) {
        keypw = CFDataCreate(NULL, (UInt8 *)data->set.str[STRING_KEY_PASSWD],
          strlen(data->set.str[STRING_KEY_PASSWD]));
      }
      if(connssl->kh) {
        DisposeIdentityKeychainHandle(connssl->kh);
        connssl->kh = NULL;
      }
      clientauth = CreateClientAuthWithCertificatesAndKeyData(certs, certdata,
                                                          keypw, &connssl->kh);
      CFRelease(certdata);
      CFRelease(certs);
      if(keypw)
        CFRelease(keypw);
      certs = clientauth;
      if(!certs) {
        failf(data, "unable to load certificate key (bad password or "
                    "cert/key mismatch?)");
        return CURLE_SSL_CERTPROBLEM;
      }
    }
    else {
      SecIdentityRef cert_and_key = NULL;
      CFTypeRef certs_c[1];
      if(data->set.str[STRING_KEY]) {
        infof(data, "WARNING: SSL: CURLOPT_SSLKEY is ignored by Secure Trans"
                    "port when CURLOPT_SSLCERT is a Keychain item label.\n");
      }
      if(data->set.str[STRING_KEY_PASSWD]) {
        infof(data, "WARNING: SSL: CURLOPT_SSLKEYPASSWD is ignored by Secure T"
                    "ransport when CURLOPT_SSLCERT is a Keychain item label.\n"
             );
      }
      err = CopyIdentityWithLabel(data->set.str[STRING_CERT], &cert_and_key);
      if(err) {
        switch(err) {
          case errSecAuthFailed: case -25264: /* errSecPkcs12VerifyFailure */
            failf(data, "SSL: Incorrect password for the certificate \"%s\" "
                        "and its private key.", data->set.str[STRING_CERT]);
            break;
          case -26275: /* errSecDecode */ case -25257:/* errSecUnknownFormat */
            failf(data, "SSL: Couldn't make sense of the data in the "
                        "certificate \"%s\" and its private key.",
                        data->set.str[STRING_CERT]);
            break;
          case -25260: /* errSecPassphraseRequired */
            failf(data, "SSL The certificate \"%s\" requires a password.",
                        data->set.str[STRING_CERT]);
            break;
          case errSecItemNotFound:
            failf(data, "SSL: Can't find the certificate \"%s\" and its privat"
                        "e key in the Keychain.", data->set.str[STRING_CERT]);
            break;
          default:
            failf(data, "SSL: Can't load the certificate \"%s\" and its privat"
                        "e key: OSStatus %d", data->set.str[STRING_CERT], err);
            break;
        }
        return CURLE_SSL_CERTPROBLEM;
      }
      certs_c[0] = cert_and_key;
      certs = CFArrayCreate(NULL, (const void **)certs_c, 1L,
                            &kCFTypeArrayCallBacks);
    }
    if(certs && CFArrayGetCount(certs) >= 1 &&
      CFGetTypeID(CFArrayGetValueAtIndex(certs,0)) == SecIdentityGetTypeID()) {
      SecCertificateRef cert = NULL;

      /* If we found one, print it out: */
      err = SecIdentityCopyCertificate(
                      (SecIdentityRef)CFArrayGetValueAtIndex(certs, 0), &cert);
      if(err == noErr) {
        CFStringRef cert_summary = CopyCertSubject(cert);
        char cert_summary_c[128];

        if(cert_summary) {
          memset(cert_summary_c, 0, 128);
          if(CFStringGetCString(cert_summary,
                                cert_summary_c,
                                128,
                                kCFStringEncodingUTF8)) {
            infof(data, "Client certificate: %s\n", cert_summary_c);
          }
          CFRelease(cert_summary);
          CFRelease(cert);
        }
      }
    }
    err = SSLSetCertificate(connssl->ssl_ctx, certs);
    if(certs)
      CFRelease(certs);
    if(err != noErr) {
      failf(data, "SSL: SSLSetCertificate() failed: OSStatus %d", err);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  err = SSLSetEnableCertVerify(connssl->ssl_ctx,
                               data->set.ssl.verifypeer?true:false);
  if(err != noErr) {
    failf(data, "SSL: SSLSetEnableCertVerify() failed: OSStatus %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }
  if(data->set.ssl.verifypeer) {
    /* The default anchors will be used unless SSLSetTrustedRoots is called
     * with an array containing at least 1 element */
    if(data->set.str[STRING_SSL_CAPATH]) {
      failf(data, "SSL: CURLOPT_CAPATH is not supported by Secure Transport");
      return CURLE_SSL_CACERT;
    }
    if(data->set.str[STRING_SSL_CAFILE]) {
      errinfo_t e;
      CFArrayRef cacerts;
      CFDataRef cadata = CFDataCreateWithContentsOfFile(kCFAllocatorDefault,
                                             data->set.str[STRING_SSL_CAFILE]);

      if(!cadata) {
        failf(data, "SSL: can't read CA certificate file %s",
              data->set.str[STRING_SSL_CAFILE]);
        return CURLE_SSL_CACERT_BADFILE;
      }
      e.f = (errinfo_func_t)failf;
      e.u = data;
      cacerts = CreateCertsArrayWithData(cadata, &e);
      CFRelease(cadata);
      if(!cacerts) {
        failf(data, "SSL: can't load CA certificate file %s",
              data->set.str[STRING_SSL_CAFILE]);
        return CURLE_SSL_CACERT_BADFILE;
      }
      err = cSSLSetTrustedRoots(connssl->ssl_ctx, cacerts, true);
      if(err != noErr) {
        failf(data, "SSL: SSLSetTrustedRoots() failed: OSStatus %d", err);
        return CURLE_SSL_CACERT_BADFILE;
      }
    }
  }
  else {
    if(data->set.str[STRING_SSL_CAFILE] || data->set.str[STRING_SSL_CAPATH]) {
      failf(data, "SSL: CA certificate set, but certificate verification "
                  "is disabled");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Configure hostname check. SNI is used if available.
   * Both hostname check and SNI require SSLSetPeerDomainName().
   * Also: the verifyhost setting influences SNI usage */
  /*if(data->set.ssl.verifyhost)*/ {
    err = SSLSetPeerDomainName(connssl->ssl_ctx, conn->host.name,
                               strlen(conn->host.name));

    if(err != noErr) {
      infof(data, "WARNING: SSL: SSLSetPeerDomainName() failed: OSStatus %d\n",
            err);
    }

    if((Curl_inet_pton(AF_INET, conn->host.name, &addr))
  #ifdef ENABLE_IPV6
    || (Curl_inet_pton(AF_INET6, conn->host.name, &addr))
  #endif
       ) {
         infof(data, "WARNING: using IP address, SNI is being disabled by "
         "the OS.\n");
    }
  }

  /* Disable cipher suites that ST supports but are not safe. These ciphers
     are unlikely to be used in any case since ST gives other ciphers a much
     higher priority, but it's probably better that we not connect at all than
     to give the user a false sense of security if the server only supports
     insecure ciphers. (Note: We don't care about SSLv2-only ciphers.) */
  (void)SSLGetNumberSupportedCiphers(connssl->ssl_ctx, &all_ciphers_count);
  all_ciphers = malloc(all_ciphers_count*sizeof(SSLCipherSuite));
  allowed_ciphers = malloc(all_ciphers_count*sizeof(SSLCipherSuite));
  if(all_ciphers && allowed_ciphers &&
     SSLGetSupportedCiphers(connssl->ssl_ctx, all_ciphers,
       &all_ciphers_count) == noErr) {
    for(i = 0UL ; i < all_ciphers_count ; i++) {
      /* There's a known bug in early versions of Mountain Lion where ST's ECC
         ciphers (cipher suite 0xC001 through 0xC032) simply do not work.
         Work around the problem here by disabling those ciphers if we are
         running in an affected version of OS X. */
      if(kCFCoreFoundationVersionNumber>=kCFCoreFoundationVersionNumber10_8 &&
         kCFCoreFoundationVersionNumber<=kCFCoreFoundationVersionNumber10_8_3
         && all_ciphers[i] >= TLS_ECDH_ECDSA_WITH_NULL_SHA
         && all_ciphers[i] <= TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384) {
           continue;
      }
      switch(all_ciphers[i]) {
        /* Disable NULL ciphersuites: */
        case SSL_NULL_WITH_NULL_NULL:
        case SSL_RSA_WITH_NULL_MD5:
        case SSL_RSA_WITH_NULL_SHA:
        case TLS_RSA_WITH_NULL_SHA256:
        case SSL_FORTEZZA_DMS_WITH_NULL_SHA:
        case TLS_ECDH_ECDSA_WITH_NULL_SHA:
        case TLS_ECDHE_ECDSA_WITH_NULL_SHA:
        case TLS_ECDH_RSA_WITH_NULL_SHA:
        case TLS_ECDHE_RSA_WITH_NULL_SHA:
        case TLS_PSK_WITH_NULL_SHA:
        case TLS_DHE_PSK_WITH_NULL_SHA:
        case TLS_RSA_PSK_WITH_NULL_SHA:
        case TLS_PSK_WITH_NULL_SHA256:
        case TLS_PSK_WITH_NULL_SHA384:
        case TLS_DHE_PSK_WITH_NULL_SHA256:
        case TLS_DHE_PSK_WITH_NULL_SHA384:
        case TLS_RSA_PSK_WITH_NULL_SHA256:
        case TLS_RSA_PSK_WITH_NULL_SHA384:
        /* Disable anonymous ciphersuites: */
        case SSL_DH_anon_EXPORT_WITH_RC4_40_MD5:
        case SSL_DH_anon_WITH_RC4_128_MD5:
        case SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DH_anon_WITH_DES_CBC_SHA:
        case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
        case TLS_DH_anon_WITH_AES_128_CBC_SHA:
        case TLS_DH_anon_WITH_AES_256_CBC_SHA:
        case TLS_ECDH_anon_WITH_NULL_SHA:
        case TLS_ECDH_anon_WITH_RC4_128_SHA:
        case TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
        case TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
        case TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
        case TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        /* Disable weak key ciphersuites: */
        case SSL_RSA_EXPORT_WITH_RC4_40_MD5:
        case SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
        case SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_RSA_WITH_DES_CBC_SHA:
        case SSL_DH_DSS_WITH_DES_CBC_SHA:
        case SSL_DH_RSA_WITH_DES_CBC_SHA:
        case SSL_DHE_DSS_WITH_DES_CBC_SHA:
        case SSL_DHE_RSA_WITH_DES_CBC_SHA:
        /* Disable IDEA: */
        case SSL_RSA_WITH_IDEA_CBC_SHA:
        case SSL_RSA_WITH_IDEA_CBC_MD5:
          break;
        default: /* enable everything else */
          allowed_ciphers[allowed_ciphers_count++] = all_ciphers[i];
          break;
      }
    }
    err = SSLSetEnabledCiphers(connssl->ssl_ctx, allowed_ciphers,
                               allowed_ciphers_count);
    if(err != noErr) {
      failf(data, "SSL: SSLSetEnabledCiphers() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
    Curl_safefree(all_ciphers);
    Curl_safefree(allowed_ciphers);
    failf(data, "SSL: Failed to allocate memory for allowed ciphers");
    return CURLE_OUT_OF_MEMORY;
  }
  Curl_safefree(all_ciphers);
  Curl_safefree(allowed_ciphers);

  if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber10_9) {
    /* We want to enable 1/n-1 when using a CBC cipher unless the user
       specifically doesn't want us doing that: */
    cSSLSetSessionOption(connssl->ssl_ctx, kSSLSessionOptionSendOneByteRecord,
                         !data->set.ssl_enable_beast);
  }

  /* Check if there's a cached ID we can/should use here! */
  if(!Curl_ssl_getsessionid(conn, (void **)&ssl_sessionid,
    &ssl_sessionid_len)) {
    /* we got a session id, use it! */
    err = SSLSetPeerID(connssl->ssl_ctx, ssl_sessionid, ssl_sessionid_len);
    if(err != noErr) {
      failf(data, "SSL: SSLSetPeerID() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
    /* Informational message */
    infof(data, "SSL re-using session ID\n");
  }
  /* If there isn't one, then let's make one up! This has to be done prior
     to starting the handshake. */
  else {
    CURLcode retcode;

    ssl_sessionid = malloc(256*sizeof(char));
    ssl_sessionid_len = snprintf(ssl_sessionid, 256, "curl:%s:%hu",
      conn->host.name, conn->remote_port);
    err = SSLSetPeerID(connssl->ssl_ctx, ssl_sessionid, ssl_sessionid_len);
    if(err != noErr) {
      failf(data, "SSL: SSLSetPeerID() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
    retcode = Curl_ssl_addsessionid(conn, ssl_sessionid, ssl_sessionid_len);
    if(retcode!= CURLE_OK) {
      failf(data, "failed to store ssl session");
      return retcode;
    }
  }

  err = SSLSetIOFuncs(connssl->ssl_ctx, SocketRead, SocketWrite);
  if(err != noErr) {
    failf(data, "SSL: SSLSetIOFuncs() failed: OSStatus %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* pass the raw socket into the SSL layers */
  /* We need to store the FD in a constant memory address, because
   * SSLSetConnection() will not copy that address. I've found that
   * conn->sock[sockindex] may change on its own. */
  connssl->ssl_sockfd = sockfd;
  err = SSLSetConnection(connssl->ssl_ctx, connssl);
  if(err != noErr) {
    failf(data, "SSL: SSLSetConnection() failed: %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static CURLcode
darwinssl_connect_step2(struct connectdata *conn, int sockindex)
{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  OSStatus err;
  SSLCipherSuite cipher;
  SSLProtocol protocol = 0;

  DEBUGASSERT(ssl_connect_2 == connssl->connecting_state
              || ssl_connect_2_reading == connssl->connecting_state
              || ssl_connect_2_writing == connssl->connecting_state);

  /* Here goes nothing: */
  err = SSLHandshake(connssl->ssl_ctx);

  if(err != noErr) {
    switch (err) {
      case errSSLWouldBlock:  /* they're not done with us yet */
        connssl->connecting_state = connssl->ssl_direction ?
            ssl_connect_2_writing : ssl_connect_2_reading;
        return CURLE_OK;

      case errSSLServerAuthCompleted:
        failf(data, "SSL unexpected errSSLServerAuthCompleted error in "
                    "connection to %s", conn->host.name);
        return CURLE_SSL_CONNECT_ERROR;

      /* These are all certificate problems with the server: */
      case errSSLXCertChainInvalid:
        failf(data, "SSL certificate problem: Invalid certificate chain");
        return CURLE_SSL_CACERT;
      case errSSLUnknownRootCert:
        failf(data, "SSL certificate problem: Untrusted root certificate");
        return CURLE_SSL_CACERT;
      case errSSLNoRootCert:
        failf(data, "SSL certificate problem: No root certificate");
        return CURLE_SSL_CACERT;
      case errSSLCertExpired:
        failf(data, "SSL certificate problem: Certificate chain had an "
              "expired certificate");
        return CURLE_SSL_CACERT;
      case errSSLBadCert:
        failf(data, "SSL certificate problem: Couldn't understand the server "
              "certificate format");
        return CURLE_SSL_CONNECT_ERROR;

      /* These are all certificate problems with the client: */
      case errSecAuthFailed:
        failf(data, "SSL authentication failed");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLPeerHandshakeFail:
        failf(data, "SSL peer handshake failed, the server most likely "
              "requires a client certificate to connect");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLPeerUnknownCA:
        failf(data, "SSL server rejected the client certificate due to "
              "the certificate being signed by an unknown certificate "
              "authority");
        return CURLE_SSL_CONNECT_ERROR;
      case errSecNoSuchKeychain:
        failf(data, "Client could not find the key's Keychain during the SSL "
              "handshake attempt to authenticate the client");
        return CURLE_SSL_CONNECT_ERROR;

      /* This error is raised if the server's cert didn't match the server's
         host name: */
      case errSSLHostNameMismatch:
        failf(data, "SSL certificate peer verification failed, the "
              "certificate did not match \"%s\"\n", conn->host.dispname);
        return CURLE_PEER_FAILED_VERIFICATION;

      /* Generic handshake errors: */
      case errSSLConnectionRefused:
        failf(data, "Server dropped the connection during the SSL handshake");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLClosedAbort:
        failf(data, "Server aborted the SSL handshake");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLNegotiation:
        failf(data, "Could not negotiate an SSL cipher suite with the server");
        return CURLE_SSL_CONNECT_ERROR;
      /* Sometimes paramErr happens with buggy ciphers: */
      case paramErr: case errSSLInternal:
        failf(data, "Internal SSL engine error encountered during the "
              "SSL handshake");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLFatalAlert:
        failf(data, "Fatal SSL engine error encountered during the SSL "
              "handshake");
        return CURLE_SSL_CONNECT_ERROR;
      default:
        failf(data, "Unknown SSL protocol error in connection to %s:%d",
              conn->host.name, err);
        return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
    /* we have been connected fine, we're not waiting for anything else. */
    connssl->connecting_state = ssl_connect_3;

    /* Informational message */
    (void)SSLGetNegotiatedCipher(connssl->ssl_ctx, &cipher);
    (void)SSLGetNegotiatedProtocolVersion(connssl->ssl_ctx, &protocol);
    switch (protocol) {
      case kSSLProtocol2:
        infof(data, "SSL 2.0 connection using %s\n",
              SSLCipherNameForNumber(cipher));
        break;
      case kSSLProtocol3:
        infof(data, "SSL 3.0 connection using %s\n",
              SSLCipherNameForNumber(cipher));
        break;
      case kTLSProtocol1:
        infof(data, "TLS 1.0 connection using %s\n",
              TLSCipherNameForNumber(cipher));
        break;
      case kTLSProtocol11:
        infof(data, "TLS 1.1 connection using %s\n",
              TLSCipherNameForNumber(cipher));
        break;
      case kTLSProtocol12:
        infof(data, "TLS 1.2 connection using %s\n",
              TLSCipherNameForNumber(cipher));
        break;
      default:
        infof(data, "Unknown protocol connection\n");
        break;
    }

    return CURLE_OK;
  }
}

static CURLcode
darwinssl_connect_step3(struct connectdata *conn,
                        int sockindex)
{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  CFStringRef server_cert_summary;
  char server_cert_summary_c[256];
  CFArrayRef server_certs = NULL;
  SecCertificateRef server_cert;
  OSStatus err;
  CFIndex i, count;

  /* There is no step 3!
   * Well, okay, if verbose mode is on, let's print the details of the
   * server certificates. */
  err = cSSLCopyPeerCertificates(connssl->ssl_ctx, &server_certs);
  /* Just in case SSLCopyPeerCertificates() returns null too... */
  if(err == noErr && server_certs) {
    count = CFArrayGetCount(server_certs);
    if(count) {
      infof(data, "----\n");
      infof(data, "Certificate chain\n");
    }
    for(i = 0L ; i < count ; i++) {
      server_cert = (SecCertificateRef)CFArrayGetValueAtIndex(server_certs, i);
      server_cert_summary = CopyCertSubject(server_cert);
      memset(server_cert_summary_c, 0, sizeof(server_cert_summary_c));
      if(CFStringGetCString(server_cert_summary,
                            server_cert_summary_c,
                            sizeof(server_cert_summary_c),
                            kCFStringEncodingUTF8)) {
        infof(data, " %u s:%s\n", (unsigned)i, server_cert_summary_c);
      }
      CFRelease(server_cert_summary);
    }
    CFRelease(server_certs);
    if(count)
      infof(data, "----\n");
  }

  connssl->connecting_state = ssl_connect_done;
  return CURLE_OK;
}

static Curl_recv darwinssl_recv;
static Curl_send darwinssl_send;

static CURLcode
darwinssl_connect_common(struct connectdata *conn,
                         int sockindex,
                         bool nonblocking,
                         bool *done)
{
  CURLcode retcode;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1==connssl->connecting_state) {
    /* Find out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
    retcode = darwinssl_connect_step1(conn, sockindex);
    if(retcode)
      return retcode;
  }

  while(ssl_connect_2 == connssl->connecting_state ||
        ssl_connect_2_reading == connssl->connecting_state ||
        ssl_connect_2_writing == connssl->connecting_state) {

    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* if ssl is expecting something, check if it's available. */
    if(connssl->connecting_state == ssl_connect_2_reading
       || connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing ==
      connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading ==
      connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_ready(readfd, writefd, nonblocking?0:timeout_ms);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          /* timeout */
          failf(data, "SSL connection timeout");
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      /* socket is readable or writable */
    }

    /* Run transaction, and return to the caller if it failed or if this
     * connection is done nonblocking and this loop would execute again. This
     * permits the owner of a multi handle to abort a connection attempt
     * before step2 has completed while ensuring that a client using select()
     * or epoll() will always have a valid fdset to wait on.
     */
    retcode = darwinssl_connect_step2(conn, sockindex);
    if(retcode || (nonblocking &&
                   (ssl_connect_2 == connssl->connecting_state ||
                    ssl_connect_2_reading == connssl->connecting_state ||
                    ssl_connect_2_writing == connssl->connecting_state)))
      return retcode;

  } /* repeat step2 until all transactions are done. */


  if(ssl_connect_3==connssl->connecting_state) {
    retcode = darwinssl_connect_step3(conn, sockindex);
    if(retcode)
      return retcode;
  }

  if(ssl_connect_done==connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = darwinssl_recv;
    conn->send[sockindex] = darwinssl_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

CURLcode
Curl_darwinssl_connect_nonblocking(struct connectdata *conn,
                                   int sockindex,
                                   bool *done)
{
  return darwinssl_connect_common(conn, sockindex, TRUE, done);
}

CURLcode
Curl_darwinssl_connect(struct connectdata *conn,
                       int sockindex)
{
  CURLcode retcode;
  bool done = FALSE;

  retcode = darwinssl_connect_common(conn, sockindex, FALSE, &done);

  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}

void Curl_darwinssl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->ssl_ctx) {
    (void)SSLClose(connssl->ssl_ctx);
    cSSLDisposeContext(connssl->ssl_ctx);
    connssl->ssl_ctx = NULL;
  }
  connssl->ssl_sockfd = 0;
  if(connssl->kh) {
    DisposeIdentityKeychainHandle(connssl->kh);
    connssl->kh = NULL;
  }
}

void Curl_darwinssl_close_all(struct SessionHandle *data)
{
  /* SecureTransport doesn't separate sessions from contexts, so... */
  (void)data;
}

int Curl_darwinssl_shutdown(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct SessionHandle *data = conn->data;
  ssize_t nread;
  int what;
  int rc;
  char buf[120];

  if(!connssl->ssl_ctx)
    return 0;

  if(data->set.ftp_ccc != CURLFTPSSL_CCC_ACTIVE)
    return 0;

  Curl_darwinssl_close(conn, sockindex);

  rc = 0;

  what = Curl_socket_ready(conn->sock[sockindex],
                           CURL_SOCKET_BAD, SSL_SHUTDOWN_TIMEOUT);

  for(;;) {
    if(what < 0) {
      /* anything that gets here is fatally bad */
      failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
      rc = -1;
      break;
    }

    if(!what) {                                /* timeout */
      failf(data, "SSL shutdown timeout");
      break;
    }

    /* Something to read, let's do it and hope that it is the close
     notify alert from the server. No way to SSL_Read now, so use read(). */

    nread = read(conn->sock[sockindex], buf, sizeof(buf));

    if(nread < 0) {
      failf(data, "read: %s", strerror(errno));
      rc = -1;
    }

    if(nread <= 0)
      break;

    what = Curl_socket_ready(conn->sock[sockindex], CURL_SOCKET_BAD, 0);
  }

  return rc;
}

void Curl_darwinssl_session_free(void *ptr)
{
  /* ST, as of iOS 5 and Mountain Lion, has no public method of deleting a
     cached session ID inside the Security framework. There is a private
     function that does this, but I don't want to have to explain to you why I
     got your application rejected from the App Store due to the use of a
     private API, so the best we can do is free up our own char array that we
     created way back in darwinssl_connect_step1... */
  Curl_safefree(ptr);
}

size_t Curl_darwinssl_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "SecureTransport");
}

/*
 * This function uses SSLGetSessionState to determine connection status.
 *
 * Return codes:
 *     1 means the connection is still in place
 *     0 means the connection has been closed
 *    -1 means the connection status is unknown
 */
int Curl_darwinssl_check_cxn(struct connectdata *conn)
{
  struct ssl_connect_data *connssl = &conn->ssl[FIRSTSOCKET];
  OSStatus err;
  SSLSessionState state;

  if(connssl->ssl_ctx) {
    err = SSLGetSessionState(connssl->ssl_ctx, &state);
    if(err == noErr)
      return state == kSSLConnected || state == kSSLHandshake;
    return -1;
  }
  return 0;
}

bool Curl_darwinssl_data_pending(const struct connectdata *conn,
                                 int connindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[connindex];
  OSStatus err;
  size_t buffer;

  if(connssl->ssl_ctx) {  /* SSL is in use */
    err = SSLGetBufferedReadSize(connssl->ssl_ctx, &buffer);
    if(err == noErr)
      return buffer > 0UL;
    return false;
  }
  else
    return false;
}

int Curl_darwinssl_random(unsigned char *entropy,
                          size_t length)
{
  /* arc4random_buf() isn't available on cats older than Lion, so let's
     do this manually for the benefit of the older cats. */
  size_t i;
  u_int32_t random_number = 0;

  for(i = 0 ; i < length ; i++) {
    if(i % sizeof(u_int32_t) == 0)
      random_number = arc4random();
    entropy[i] = random_number & 0xFF;
    random_number >>= 8;
  }
  i = random_number = 0;
  return 0;
}

void Curl_darwinssl_md5sum(unsigned char *tmp, /* input */
                           size_t tmplen,
                           unsigned char *md5sum, /* output */
                           size_t md5len)
{
  CC_MD5_CTX ctx;
  (void)md5len;
  (void)CC_MD5_Init(&ctx);
  (void)CC_MD5_Update(&ctx, tmp, (CC_LONG)tmplen);
  (void)CC_MD5_Final(md5sum, &ctx);
}

static ssize_t darwinssl_send(struct connectdata *conn,
                              int sockindex,
                              const void *mem,
                              size_t len,
                              CURLcode *curlcode)
{
  /*struct SessionHandle *data = conn->data;*/
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  size_t processed = 0UL;
  OSStatus err;

  /* The SSLWrite() function works a little differently than expected. The
     fourth argument (processed) is currently documented in Apple's
     documentation as: "On return, the length, in bytes, of the data actually
     written."

     Now, one could interpret that as "written to the socket," but actually,
     it returns the amount of data that was written to a buffer internal to
     the SSLContextRef instead. So it's possible for SSLWrite() to return
     errSSLWouldBlock and a number of bytes "written" because those bytes were
     encrypted and written to a buffer, not to the socket.

     So if this happens, then we need to keep calling SSLWrite() over and
     over again with no new data until it quits returning errSSLWouldBlock. */

  /* Do we have buffered data to write from the last time we were called? */
  if(connssl->ssl_write_buffered_length) {
    /* Write the buffered data: */
    err = SSLWrite(connssl->ssl_ctx, NULL, 0UL, &processed);
    switch (err) {
      case noErr:
        /* processed is always going to be 0 because we didn't write to
           the buffer, so return how much was written to the socket */
        processed = connssl->ssl_write_buffered_length;
        connssl->ssl_write_buffered_length = 0UL;
        break;
      case errSSLWouldBlock: /* argh, try again */
        *curlcode = CURLE_AGAIN;
        return -1L;
      default:
        failf(conn->data, "SSLWrite() returned error %d", err);
        *curlcode = CURLE_SEND_ERROR;
        return -1L;
    }
  }
  else {
    /* We've got new data to write: */
    err = SSLWrite(connssl->ssl_ctx, mem, len, &processed);
    if(err != noErr) {
      switch (err) {
        case errSSLWouldBlock:
          /* Data was buffered but not sent, we have to tell the caller
             to try sending again, and remember how much was buffered */
          connssl->ssl_write_buffered_length = len;
          *curlcode = CURLE_AGAIN;
          return -1L;
        default:
          failf(conn->data, "SSLWrite() returned error %d", err);
          *curlcode = CURLE_SEND_ERROR;
          return -1L;
      }
    }
  }
  return (ssize_t)processed;
}

static ssize_t darwinssl_recv(struct connectdata *conn,
                              int num,
                              char *buf,
                              size_t buffersize,
                              CURLcode *curlcode)
{
  /*struct SessionHandle *data = conn->data;*/
  struct ssl_connect_data *connssl = &conn->ssl[num];
  size_t processed = 0UL;
  OSStatus err = SSLRead(connssl->ssl_ctx, buf, buffersize, &processed);

  if(err != noErr) {
    switch (err) {
      case errSSLWouldBlock:  /* return how much we read (if anything) */
        if(processed)
          return (ssize_t)processed;
        *curlcode = CURLE_AGAIN;
        return -1L;
        break;

      /* errSSLClosedGraceful - server gracefully shut down the SSL session
         errSSLClosedNoNotify - server hung up on us instead of sending a
           closure alert notice, read() is returning 0
         Either way, inform the caller that the server disconnected. */
      case errSSLClosedGraceful:
      case errSSLClosedNoNotify:
        *curlcode = CURLE_OK;
        return -1L;
        break;

      default:
        failf(conn->data, "SSLRead() return error %d", err);
        *curlcode = CURLE_RECV_ERROR;
        return -1L;
        break;
    }
  }
  return (ssize_t)processed;
}

#include "stcompat.c"

#endif /* USE_DARWINSSL */
