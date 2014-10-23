/*

stcompat.c -- SecureTransport compatibility implementation
Copyright (C) 2014 Kyle J. McKay.  All rights reserved.

If this software is included as part of a build of
the cURL library, it may be used under the same license
terms as the cURL library.

Otherwise the GPLv2 license applies.

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

*/

#include <Security/Security.h>
#include <limits.h>
#include <objc/objc-runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <dirent.h>
#include "stcompat.h"

#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))
#include <dlfcn.h>
__attribute__((constructor,used)) static void stcompat_initialize(void);
#endif /* (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)) */

extern CFStringRef NSTemporaryDirectory(void);

static CFStringRef CFCopyTemporaryDirectory(void)
{
  id pool = objc_msgSend(objc_getClass("NSAutoreleasePool"), sel_getUid("new"));
  CFStringRef dir = (CFStringRef)NSTemporaryDirectory();
  if (dir) CFRetain(dir);
  objc_msgSend(pool, sel_getUid("drain"));
  if (dir) {
    unsigned len = (unsigned)CFStringGetLength(dir);
    unsigned l = len;
    while (l > 1 &&
           (unsigned)CFStringGetCharacterAtIndex(dir, l-1) == (unsigned)'/') {
      --l;
    }
    if (l < len) {
      CFStringRef old = dir;
      dir = CFStringCreateWithSubstring(
        kCFAllocatorDefault, dir, CFRangeMake(0, l));
      if (dir)
        CFRelease(old);
      else
        dir = old;
    }
  }
  return dir;
}

CFDataRef CFDataCreateWithContentsOfFile(CFAllocatorRef a, const char *f)
{
  char buff[4096];
  CFMutableDataRef d = CFDataCreateMutable(a, 0);
  int fd;
  ssize_t cnt;
  if (!d) return NULL;
  fd = open(f, O_RDONLY);
  if (fd < 0) {
    CFRelease(d);
    return NULL;
  }
  do {
    cnt = read(fd, buff, sizeof(buff));
    if (cnt > 0) CFDataAppendBytes(d, (UInt8 *)buff, (size_t)cnt);
  } while (cnt > 0);
  close(fd);
  if (cnt) {
    CFRelease(d);
    return NULL;
  }
  return d;
}

static const char *memmem(const void *_m, size_t ml, const void *_s, size_t sl)
{
  const char *m = (const char *)_m;
  const char *s = (const char *)_s;
  if (!ml || !sl || ml < sl) return NULL;
  if (sl == 1) return memchr(m, *s, ml);
  if (ml == sl) return memcmp(m, s, sl) ? NULL : m;
  do {
    size_t o;
    const char *p = memchr(m, *s, ml);
    if (!p) return NULL;
    o = p - m;
    ml -= o;
    m += o;
    if (ml < sl) return NULL;
    if (!memcmp(m, s, sl)) return m;
    ++m;
    --ml;
  } while (ml >= sl);
  return NULL;
}

CF_INLINE int is_eol(int c)
{
  return c == '\n' || c == '\r';
}

CF_INLINE int is_lb(int c)
{
  return c == '\n' || c == '\r' || c == '\f';
}

CF_INLINE int is_prnt(int c)
{
  return c >= ' ' && c <= '~';
}

static int has_lb(const void *_m, size_t l)
{
  const char *m = (const char *)_m;
  while (l) {
    if (is_lb(*m)) return 1;
    --l;
    ++m;
  }
  return 0;
}

static int has_prnt(const void *_m, size_t l)
{
  const char *m = (const char *)_m;
  while (l) {
    if (!is_prnt(*m)) return 0;
    --l;
    ++m;
  }
  return 1;
}

/*
 * returns start of "-----BEGIN XXXX-----\n" line or NULL if not found/error
 * If returns NULL then *ot == 0 means not found, *ot == -1 means bad line
 * If returns non-NULL then *ol is length through "-----\n" and *ot is length
 * of "XXXX" part (which obviously starts at return value + 11 for BEGIN or
 * value + 9 for END)
 * If e is non-zero look for ----END rather than ----BEGIN
 */
static const char *find_be(const void *_m, size_t l, size_t *ol, int *ot, int e)
{
  const char *m = (const char *)_m;
  const char *origm = m;
  const char *marker = e ? "-----END " : "-----BEGIN ";
  size_t mkl = e ? 9 : 11;
  *ot = 0;
  while (l) {
    const char *t;
    const char *p = memmem(m, l, marker, mkl);
    if (!p) return NULL;
    l -= (p - m) + mkl;
    m = p + mkl;
    if (p > origm && !is_eol(p[-1])) continue;
    t = memmem(m, l, "-----", 5);
    if (!t) return NULL;
    l -= (t - m);
    if (l > 5 && !is_eol(t[5])) continue;
    if (has_lb(p, t-p)) continue;
    if ((size_t)(t-p) > (76 - mkl - 5) || !has_prnt(p, t-p)) {
      *ot = -1;
      return NULL;
    }
    *ot = (int)(t - m);
    l -= 5;
    m = t + 5;
    if (l && *m == '\r') {
      ++m;
      --l;
    }
    if (l && *m == '\n') {
      ++m;
      --l;
    }
    *ol = m - p;
    return p;
  }
  return NULL;
}

typedef enum {
  pemtype_unknown,
  pemtype_certificate, /* "CERTIFICATE" or "TRUSTED CERTIFICATE" */
  pemtype_privatekey_rsa /* "RSA PRIVATE KEY" */
} pemtype_t;

typedef struct {
  const char *start;  /* Armour start "-----BEGIN XXXXX-----\n" */
  size_t len; /* Length through armour end "-----END XXXXX-----\n" */
  /* Body starts after "-----BEGIN XXXXX-----\n" */
  const char *body;
  size_t bodylen; /* Length though "\n" BEFORE final "-----END XXXXX-----\n" */
  /* Kind starts at start + 11 */
  size_t kindlen; /* length of "XXXXX" from "-----BEGIN XXXXX-----\n" */
  pemtype_t type;
} peminfo_t;

static int nextpem(const char *p, size_t l, peminfo_t *o)
{
  size_t beglen, endlen;
  int begtype, endtype;
  const char *end;
  const char *beg = find_be(p, l, &beglen, &begtype, 0);
  if (!beg) return begtype;
  end = find_be(p + beglen, l - beglen, &endlen, &endtype, 1);
  if (!end || begtype != endtype || memcmp(beg+11, end+9, (size_t)begtype))
    return -1;
  o->start = beg;
  o->len = (end + endlen) - beg;
  o->body = beg + beglen;
  o->bodylen = end - (beg + beglen);
  o->kindlen = (size_t)begtype;
  if (begtype == 11 && !memcmp(beg + 11, "CERTIFICATE", 11)) {
    o->type = pemtype_certificate;
  } else if (begtype == 19 && !memcmp(beg + 11, "TRUSTED CERTIFICATE", 19)) {
    o->type = pemtype_certificate;
  } else if (begtype == 15 && !memcmp(beg + 11, "RSA PRIVATE KEY", 15)) {
    o->type = pemtype_privatekey_rsa;
  } else {
    o->type = pemtype_unknown;
  }
  return (int)((o->start + o->len) - p);
}

static const signed char b64tab[256] = {
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,0x3E,-1,-1,-1,0x3F,
0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,-1,-1,-1,0x40,-1,-1,
-1,0,1,2,3,4,5,6,7,8,9,0x0A,0x0B,0x0C,0x0D,0x0E,
0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,-1,-1,-1,-1,-1,
-1,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static void convert24(const uint8_t *input, uint8_t *output)
{
  output[0] = ((b64tab[input[0]]&0x3F)<<2)|((b64tab[input[1]]&0x3F)>>4);
  output[1] = (((b64tab[input[1]]&0x3F)&0x0F)<<4)|((b64tab[input[2]]&0x3F)>>2);
  output[2] = (((b64tab[input[2]]&0x3F)&0x03)<<6)|(b64tab[input[3]]&0x3F);
}

static CFDataRef CFDataCreateFromBase64(CFAllocatorRef a, const void *_b, size_t l)
{
  uint8_t inp[4];
  uint8_t out[3];
  int i;
  CFMutableDataRef d;
  const uint8_t *p = (uint8_t *)_b;
  if (l && !p) return NULL;
  d = CFDataCreateMutable(a, 0);
  if (!d) return NULL;
  if (!l) return d;
  for (i=0; l; ++p, --l) {
    uint8_t c = *p;
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f')
      continue;
    if (b64tab[c] < 0) {
      CFRelease(d);
      return NULL;
    }
    inp[i++] = c;
    if (i == 4) {
      convert24(inp, out);
      i = 0;
      if (inp[3] == '=') {
        CFDataAppendBytes(d, out, inp[2] == '=' ? 1 : 2);
        break;
      }
      CFDataAppendBytes(d, out, 3);
    }
  }
  if (i != 0) {
    CFRelease(d);
    return NULL;
  }
  return d;
}

static SecCertificateRef createvalidcert(CFDataRef d)
{
  SecCertificateRef cert = cSecCertificateCreateWithData(kCFAllocatorDefault, d);
  if (!cert) return NULL;
  if (!CheckCertOkay(cert)) {
    CFRelease(cert);
    return NULL;
  }
  return cert;
}

CFArrayRef CreateCertsArrayWithData(CFDataRef d, const errinfo_t *e)
{
  const char *certs, *p;
  size_t certslen, plen, cnt = 1;
  CFMutableArrayRef a;
  if (!d) return NULL;
  certs = (char *)CFDataGetBytePtr(d);
  certslen = (size_t)CFDataGetLength(d);
  a = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  if (!a) return NULL;
  p = certs;
  plen = certslen;
  while (plen) {
    peminfo_t pem;
    int readcnt = nextpem(p, plen, &pem);
    if (!readcnt && p == certs) {
      /* assume it's a DER cert */
      SecCertificateRef cert;
      CFDataRef der = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
                                   (UInt8 *)certs, certslen, kCFAllocatorNull);
      if (!der) {
        CFRelease(a);
        return NULL;
      }
      cert = createvalidcert(der);
      CFRelease(der);
      if (!cert) {
        if (e)
          e->f(e->u, "Invalid CA certificate bad DER data\n");
        CFRelease(a);
        return NULL;
      }
      CFArrayAppendValue(a, cert);
      CFRelease(cert);
      return a;
    } else if (readcnt == -1) {
      if (e)
        e->f(e->u, "Invalid CA certificate #%u (offset %u) in bundle\n",
                   (unsigned)cnt, (unsigned)(p-certs));
      CFRelease(a);
      return NULL;
    } else if (readcnt && pem.type == pemtype_certificate) {
      CFDataRef der = CFDataCreateFromBase64(kCFAllocatorDefault, pem.body, pem.bodylen);
      SecCertificateRef cert;
      if (!der) {
        if (e)
          e->f(e->u, "Invalid CA certificate #%u (offset %u) bad base 64 in bundle\n",
                     (unsigned)cnt, (unsigned)(pem.start-certs));
        CFRelease(a);
        return NULL;
      }
      cert = createvalidcert(der);
      CFRelease(der);
      if (!cert) {
        if (e)
          e->f(e->u, "Invalid CA certificate #%u (offset %u) bad cert data in bundle\n",
                     (unsigned)cnt, (unsigned)(pem.start-certs));
        CFRelease(a);
        return NULL;
      }
      CFArrayAppendValue(a, cert);
      CFRelease(cert);
      ++cnt;
    } else if (!readcnt) break;
    plen -= (pem.start + pem.len) - p;
    p = pem.start + pem.len;
  }
  return a;
}

static char *new_temp_keych(void)
{
  char *ans;
  char newdir[PATH_MAX];
  Boolean okay;
  CFStringRef tempdir = CFCopyTemporaryDirectory();
  if (!tempdir) return NULL;
  okay = CFStringGetCString(tempdir, newdir, sizeof(newdir) - 32, kCFStringEncodingUTF8);
  CFRelease(tempdir);
  if (!okay) return NULL;
  strcat(newdir, "/tch.XXXXXX");
  ans = (char *)malloc(strlen(newdir) + 1 + 14 /* "/temp.keychain" */);
  if (!ans) return NULL;
  strcpy(ans, newdir);
  if (!mkdtemp(ans)) return NULL;
  strcat(ans, "/temp.keychain");
  return ans;
}

static void del_temp_keych(char *keych)
{
  size_t l;
  if (!keych) return;
  l = strlen(keych);
  if (l > 14 && !strcmp(keych + (l - 14), "/temp.keychain")) {
    DIR *d;
    unlink(keych);
    keych[l - 14] = '\0';
    /* the keychain code leaves dot turds (and possibly comma turds) we have to remove */
    d = opendir(keych);
    if (d) {
      struct dirent *ent;
      while ((ent=readdir(d)) != NULL) {
        char turd[PATH_MAX];
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0'
             || (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) continue;
        if (ent->d_name[0] != '.' && ent->d_name[0] != ',') continue;
        snprintf(turd, sizeof(turd), "%s/%s", keych, ent->d_name);
        unlink(turd);
      }
      closedir(d);
    }
    rmdir(keych);
    free(keych);
  }
}

static CFDataRef extract_key_copy(CFDataRef pemseq, int *outpem)
{
  const char *p = (char *)CFDataGetBytePtr(pemseq);
  const char *origp = p;
  size_t l = (size_t)CFDataGetLength(pemseq);
  size_t origl = l;
  *outpem = 0;
  while (l) {
    peminfo_t pem;
    int readcnt = nextpem(p, l, &pem);
    if (!readcnt && p == origp) {
      /* Assume it's DER data */
      CFRetain(pemseq);
      return pemseq;
    }
    if (!readcnt || readcnt == -1) return NULL;
    if (pem.type == pemtype_privatekey_rsa) {
      *outpem = 1;
      if (pem.start == origp && pem.len == origl) {
        CFRetain(pemseq);
        return pemseq;
      }
      return CFDataCreate(kCFAllocatorDefault, (uint8_t *)pem.start, pem.len);
    }
    l -= (size_t)readcnt;
    p += (size_t)readcnt;
  }
  return NULL;
}

SecIdentityRef cSecIdentityCreateWithCertificateAndKeyData(
  SecCertificateRef cert, CFDataRef keydata, CFTypeRef pw)
{
  int ispem;
  CFDataRef rawkey = NULL;
  char *keych = NULL;
  int err;
  SecKeychainRef keychain = NULL;
  SecExternalFormat format;
  SecExternalItemType type;
  SecItemImportExportKeyParameters params;
  CFArrayRef items = NULL;
  SecKeyRef key = NULL;
  SecIdentityRef ans = NULL;

  if (!cert) return NULL;
  if (keydata)
    rawkey = extract_key_copy(keydata, &ispem);
  while (rawkey) {
    CFArrayRef searchlist = NULL;
    keych = new_temp_keych();
    if (!keych) break;
    /* SecKeychainCreate has the side effect of adding the new keychain to
     * the search list which will make it show up in other apps.
     * SecKeychainDelete removes it from the search list, or we can also get
     * the search list before the create and restore it right after.
     * By immediately restoring the search list, we avoid having the new
     * private key we're importing be searchable by default in other apps. */
    err = SecKeychainCopySearchList(&searchlist);
    if (err || !searchlist) break;
    err = SecKeychainCreate(keych, 8, "password", false, NULL, &keychain);
    if (err || !keychain) {
      CFRelease(searchlist);
      break;
    }
    err = SecKeychainSetSearchList(searchlist);
    CFRelease(searchlist);
    if (err) {
      SecKeychainDelete(keychain);
      break;
    }
    err = SecKeychainUnlock(keychain, 8, "password", true);
    if (err) break;
    format = ispem ? kSecFormatWrappedOpenSSL : kSecFormatOpenSSL;
    type = kSecItemTypePrivateKey;
    memset(&params, 0, sizeof(params));
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = kSecKeyImportOnlyOne|kSecKeyNoAccessControl;
    if (pw)
      params.passphrase = pw;
    else
      params.flags |= kSecKeySecurePassphrase;
    err = cSecItemImport(rawkey, NULL, &format, &type,
      ispem?kSecItemPemArmour:0, &params, keychain, &items);
    CFRelease(rawkey);
    if (!err && items && CFArrayGetCount(items) == 1 &&
      CFGetTypeID((CFTypeRef)CFArrayGetValueAtIndex(items, 0)) == SecKeyGetTypeID()) {
      key = (SecKeyRef)CFArrayGetValueAtIndex(items, 0);
      CFRetain(key);
    }
    if (items) CFRelease(items);
    break;
  }
  if (key) {
    err = cSecIdentityCreateWithCertificate(keychain, cert, &ans);
    CFRelease(key);
  }
  /* We MUST NOT call SecKeychainDelete because that will purge all copies of
   * the keychain from memory.  We've already removed it from the search list
   * so we just release it and remove the disk files instead in order to allow
   * the in memory copy to remain unmolested. */
  if (keychain) CFRelease(keychain);
  if (keych) del_temp_keych(keych);
  if (!ans && key && keychain) {
    /* Try again with the default keychain list */
    err = cSecIdentityCreateWithCertificate(NULL, cert, &ans);
  }
  return ans;
}

CFArrayRef CreateClientAuthWithCertificatesAndKeyData(CFArrayRef certs,
                                              CFDataRef keydata, CFTypeRef pw)
{
  CFMutableArrayRef ans;
  size_t count, i;
  SecCertificateRef cert;
  SecIdentityRef identity;

  if (!certs || !keydata) return NULL;
  count = (size_t)CFArrayGetCount(certs);
  if (count < 1) return NULL;
  cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, 0);
  if (CFGetTypeID(cert) != SecCertificateGetTypeID()) return NULL;
  ans = CFArrayCreateMutable(kCFAllocatorDefault, count, &kCFTypeArrayCallBacks);
  if (!ans) return NULL;
  identity = cSecIdentityCreateWithCertificateAndKeyData(cert, keydata, pw);
  if (!identity) {
    CFRelease(ans);
    return NULL;
  }
  CFArrayAppendValue(ans, identity);
  for (i = 1; i < count; ++i) {
    CFArrayAppendValue(ans, CFArrayGetValueAtIndex(certs, i));
  }
  return ans;
}

#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))

#ifndef kCFCoreFoundationVersionNumber10_8
#define kCFCoreFoundationVersionNumber10_8 744.00
#endif

typedef enum {
  small_0,
  small_1,
  small_2,
  small_3,
  small_4,
  small_5
} SmallEnum;

static struct {
  OSStatus (*fSSLSetTrustedRoots)(SSLContextRef,CFArrayRef,Boolean);
  OSStatus (*fSSLGetPeerCertificates)(SSLContextRef cxt, CFArrayRef *certs);
  OSStatus (*fSSLCopyPeerCertificates)(SSLContextRef cxt, CFArrayRef *certs);
  OSStatus (*fSSLSetProtocolVersionEnabled)(SSLContextRef cxt, SmallEnum, Boolean);
  OSStatus (*fSSLSetProtocolVersionMin)(SSLContextRef cxt, SmallEnum);
  OSStatus (*fSSLSetProtocolVersionMax)(SSLContextRef cxt, SmallEnum);
  OSStatus (*fSSLSetSessionOption)(SSLContextRef, SmallEnum, Boolean);
  SecCertificateRef (*fSecCertificateCreateWithData)(CFAllocatorRef, CFDataRef);
  OSStatus (*fSecCertificateCreateFromData)(const CSSM_DATA *, CSSM_CERT_TYPE,
                                      CSSM_CERT_ENCODING, SecCertificateRef *);
  OSStatus (*fSecCertificateGetCLHandle)(SecCertificateRef, CSSM_CL_HANDLE *);
  OSStatus (*fSecCertificateGetData)(SecCertificateRef, CSSM_DATA_PTR);
  OSStatus (*fSecCertificateCopyCommonName)(SecCertificateRef, CFStringRef *);
  CFStringRef (*fSecCertificateCopySubjectSummary)(SecCertificateRef);
  CFStringRef (*fSecCertificateCopyLongDescription)(CFAllocatorRef, SecCertificateRef, CFTypeRef *);
  SecIdentityRef (*fSecIdentityCreate)(CFAllocatorRef, SecCertificateRef, SecKeyRef);
  OSStatus (*fSecKeychainItemImport)(
    CFDataRef,CFStringRef,SecExternalFormat *,SecExternalItemType *,
    SecItemImportExportFlags,const SecKeyImportExportParameters *,
    SecKeychainRef,CFArrayRef *);
  OSStatus (*fSecItemImport)(
    CFDataRef,CFStringRef,SecExternalFormat *,SecExternalItemType *,
    SecItemImportExportFlags,const SecItemImportExportKeyParameters *,
    SecKeychainRef,CFArrayRef *);
  OSStatus (*fSecIdentityCreateWithCertificate)(CFTypeRef,SecCertificateRef,SecIdentityRef *);
  OSStatus (*fSSLNewContext)(Boolean,SSLContextRef *);
  OSStatus (*fSSLDisposeContext)(SSLContextRef);
  SSLContextRef (*fSSLCreateContext)(CFAllocatorRef,SmallEnum,SmallEnum);
  OSStatus (*fSecKeychainSearchCreateFromAttributes)(CFTypeRef,int,
            const SecKeychainAttributeList *,SecKeychainSearchRef *);
  OSStatus (*fSecKeychainSearchCopyNext)(SecKeychainSearchRef,SecKeychainItemRef *);
} fnc;

static void stcompat_initialize(void)
{
#define LOOKUP(name) *((void **)&fnc.f##name) = dlsym(RTLD_NEXT, #name)
  LOOKUP(SSLSetTrustedRoots);
  LOOKUP(SSLGetPeerCertificates);
  LOOKUP(SSLCopyPeerCertificates);
  LOOKUP(SSLSetProtocolVersionEnabled);
  LOOKUP(SSLSetProtocolVersionMin);
  LOOKUP(SSLSetProtocolVersionMax);
  LOOKUP(SSLSetSessionOption);
  LOOKUP(SecCertificateCreateWithData);
  LOOKUP(SecCertificateCreateFromData);
  LOOKUP(SecCertificateGetCLHandle);
  LOOKUP(SecCertificateGetData);
  LOOKUP(SecCertificateCopyCommonName);
  LOOKUP(SecCertificateCopySubjectSummary);
  LOOKUP(SecCertificateCopyLongDescription);
  LOOKUP(SecIdentityCreate);
  LOOKUP(SecKeychainItemImport);
  LOOKUP(SecItemImport);
  LOOKUP(SecIdentityCreateWithCertificate);
  LOOKUP(SSLNewContext);
  LOOKUP(SSLDisposeContext);
  LOOKUP(SSLCreateContext);
  LOOKUP(SecKeychainSearchCreateFromAttributes);
  LOOKUP(SecKeychainSearchCopyNext);
#undef LOOKUP
}

OSStatus cSSLSetTrustedRoots(SSLContextRef cxt, CFArrayRef rts, Boolean replace)
{
  if (fnc.fSSLSetTrustedRoots)
    return fnc.fSSLSetTrustedRoots(cxt, rts, replace);
  return unimpErr;
}

OSStatus cSSLCopyPeerCertificates(SSLContextRef cxt, CFArrayRef *certs)
{
  if (!certs || !cxt) return paramErr;
  *certs = NULL;
  if (fnc.fSSLCopyPeerCertificates)
    return fnc.fSSLCopyPeerCertificates(cxt, certs);
  if (fnc.fSSLGetPeerCertificates) {
    OSStatus err = fnc.fSSLGetPeerCertificates(cxt, certs);
    if (!err && *certs) {
      size_t i, c = (size_t)CFArrayGetCount(*certs);
      for (i = 0; i < c; ++i) {
        CFTypeRef item = (CFTypeRef)CFArrayGetValueAtIndex(*certs, i);
        if (item) CFRelease(item);
      }
    }
    return err;
  }
  return unimpErr;
}

OSStatus cSSLSetProtocolVersionMinMax(SSLContextRef cxt, int minVer, int maxVer)
{
  OSStatus err;

  if (minVer < 0 || maxVer < 0 || minVer > 8 || maxVer > 8 || minVer > maxVer)
    return paramErr;

  if (minVer == kSSLProtocolUnknown) minVer = kSSLProtocol3;
  if (minVer == kSSLProtocolAll)     minVer = kSSLProtocol3;
  if (minVer == kSSLProtocol3Only)   minVer = kSSLProtocol3;
  if (minVer == kTLSProtocol1Only)   minVer = kTLSProtocol1;

  if (maxVer == kSSLProtocol3Only)   maxVer = kSSLProtocol3;
  if (maxVer == kTLSProtocol1Only)   maxVer = kTLSProtocol1;
  if (maxVer == kSSLProtocolAll)     maxVer = kTLSProtocol12;
  if (maxVer == kSSLProtocolUnknown) maxVer = kTLSProtocol12;

  if (kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber10_8 &&
      minVer <= kTLSProtocol1 && maxVer > kTLSProtocol1)
    maxVer = kTLSProtocol1;

  if (fnc.fSSLSetProtocolVersionMin && fnc.fSSLSetProtocolVersionMax) {
    err = fnc.fSSLSetProtocolVersionMin(cxt, minVer);
    if (!err)
      err = fnc.fSSLSetProtocolVersionMax(cxt, maxVer);
    return err;
  }
  if (fnc.fSSLSetProtocolVersionEnabled) {
#define ENABLEPROTO(x) fnc.fSSLSetProtocolVersionEnabled(cxt, (int)(x), \
                           minVer <= x && x <= maxVer)
    err = ENABLEPROTO(kSSLProtocol2);
    if (err && minVer > kSSLProtocol2) err = noErr; /* ignore SSL2 disable error */
    if (!err) ENABLEPROTO(kSSLProtocol3);
    if (!err) ENABLEPROTO(kTLSProtocol1);
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber10_8 ||
        maxVer > kTLSProtocol1) {
      if (!err) ENABLEPROTO(kTLSProtocol11);
      if (!err) ENABLEPROTO(kTLSProtocol12);
    }
#undef ENABLEPROTO
    return err;
  }
  return unimpErr;
}

OSStatus cSSLSetSessionOption(SSLContextRef cxt, int option, Boolean value)
{
  if (fnc.fSSLSetSessionOption)
    return fnc.fSSLSetSessionOption(cxt, option, value);
  else
    return unimpErr;
}

SecCertificateRef cSecCertificateCreateWithData(CFAllocatorRef a, CFDataRef d)
{
  if (fnc.fSecCertificateCreateWithData)
    return fnc.fSecCertificateCreateWithData(a, d);
  else if (fnc.fSecCertificateCreateFromData) {
    CSSM_DATA certdata;
    OSStatus err;
    SecCertificateRef cacert = NULL;
    if (!d) return NULL;
    certdata.Length = (size_t)CFDataGetLength(d);
    certdata.Data = (uint8 *)CFDataGetBytePtr(d);
    err = fnc.fSecCertificateCreateFromData(&certdata, CSSM_CERT_X_509v3,
                                            CSSM_CERT_ENCODING_DER, &cacert);
    if (err)
      cacert = NULL;
    return cacert;
  } else
    return NULL;
}

static int oids_match(const CSSM_OID *o1, const CSSM_OID *o2)
{
  if (!o1 || !o2 || !o1->Length || !o2->Length || o1->Length != o2->Length)
    return 0;
  return memcmp(o1->Data, o2->Data, o1->Length) == 0;
}

OSStatus CopyIdentityWithLabel(const char *label, SecIdentityRef *out)
{
  if (fnc.fSecKeychainSearchCreateFromAttributes &&
      fnc.fSecKeychainSearchCopyNext) {
    SecIdentityRef ans = NULL;
    SecCertificateRef cert = NULL;
    SecKeychainAttribute at;
    SecKeychainAttributeList al;
    SecKeychainSearchRef sr;
    OSStatus err;

    at.tag = kSecLabelItemAttr;
    at.length = strlen(label);
    at.data = (char *)label;
    al.count = 1;
    al.attr = &at;
    err = fnc.fSecKeychainSearchCreateFromAttributes(NULL,
                                           kSecCertificateItemClass, &al, &sr);
    *out = NULL;
    if (err || !sr) return err;
    while ((err = fnc.fSecKeychainSearchCopyNext(sr, (SecKeychainItemRef *)&cert)) == noErr) {
      if (!cert) continue;
      if (CFGetTypeID(cert) != SecCertificateGetTypeID()) {CFRelease(cert); continue;}
      err = cSecIdentityCreateWithCertificate(NULL, cert, &ans);
      CFRelease(cert);
      if (!err && ans) break;
    }
    CFRelease(sr);
    if (ans) {
      *out = ans;
      return noErr;
    }
    return errSecItemNotFound;
  }
  return unimpErr;
}

CFStringRef CopyCertSubject(SecCertificateRef cert)
{
  if (fnc.fSecCertificateCopyLongDescription)
    return fnc.fSecCertificateCopyLongDescription(kCFAllocatorDefault, cert, NULL);
  if (fnc.fSecCertificateCopySubjectSummary)
    return fnc.fSecCertificateCopySubjectSummary(cert);
  if (fnc.fSecCertificateCopyCommonName) {
    CFStringRef ans = NULL;
    OSStatus err = fnc.fSecCertificateCopyCommonName(cert, &ans);
    if (err) ans = NULL;
    return ans;
  }
  if (fnc.fSecCertificateGetCLHandle && fnc.fSecCertificateGetData) {
    CSSM_CL_HANDLE h = 0;
    CSSM_DATA certdata;
    CSSM_DATA_PTR fv;
    CSSM_X509_NAME_PTR name;
    CSSM_HANDLE results;
    CSSM_RETURN result;
    uint32 cnt, i;
    int found = 0;
    CFStringRef ans = NULL;
    OSStatus err = fnc.fSecCertificateGetData(cert, &certdata);
    if (err) return NULL;
    err = fnc.fSecCertificateGetCLHandle(cert, &h);
    if (err || !h) return NULL;
    result = CSSM_CL_CertGetFirstFieldValue(h, &certdata,
      &CSSMOID_X509V1SubjectNameCStruct, &results, &cnt, &fv);
    if (result || !fv || !fv->Data)
      return NULL;
    name = (CSSM_X509_NAME_PTR)fv->Data;
    for (i = 0; !found && i < name->numberOfRDNs; ++i) {
      uint32_t j;
      CSSM_X509_RDN_PTR rdn = &name->RelativeDistinguishedName[i];
      for (j = 0; j < rdn->numberOfPairs; ++j) {
        CSSM_X509_TYPE_VALUE_PAIR_PTR tp = &rdn->AttributeTypeAndValue[j];
        if (oids_match(&tp->type, &CSSMOID_CommonName)) {
          CFStringBuiltInEncodings encoding;
          switch (tp->valueType) {
            case BER_TAG_PRINTABLE_STRING:
            case BER_TAG_IA5_STRING:
              encoding = kCFStringEncodingASCII; break;
            case BER_TAG_PKIX_UTF8_STRING:
            case BER_TAG_GENERAL_STRING:
            case BER_TAG_PKIX_UNIVERSAL_STRING:
              encoding = kCFStringEncodingUTF8; break;
            case BER_TAG_T61_STRING:
            case BER_TAG_VIDEOTEX_STRING:
            case BER_TAG_ISO646_STRING:
              encoding = kCFStringEncodingISOLatin1; break;
            case BER_TAG_PKIX_BMP_STRING:
              encoding = kCFStringEncodingUnicode; break;
            default:
              continue;
          }
          ans = CFStringCreateWithBytes(kCFAllocatorDefault, tp->value.Data,
                                        (size_t)tp->value.Length, encoding, true);
          if (ans) {
            found = 1;
            break;
          }
        }
      }
    }
    CSSM_CL_CertAbortQuery(h, results);
    return ans;
  }
  return NULL;
}

Boolean CheckCertOkay(SecCertificateRef cert)
{
  if (fnc.fSecCertificateGetCLHandle && fnc.fSecCertificateGetData) {
    CSSM_CL_HANDLE h = 0;
    CSSM_DATA certdata;
    CSSM_DATA_PTR fv;
    CSSM_X509_NAME_PTR name;
    CSSM_HANDLE results;
    CSSM_RETURN result;
    uint32 cnt, i;
    int found = 0;
    OSStatus err = fnc.fSecCertificateGetData(cert, &certdata);
    if (err) return false;
    err = fnc.fSecCertificateGetCLHandle(cert, &h);
    if (err || !h) return false;
    result = CSSM_CL_CertGetFirstFieldValue(h, &certdata,
      &CSSMOID_X509V1SubjectNameCStruct, &results, &cnt, &fv);
    if (result || !fv || !fv->Data)
      return false;
    name = (CSSM_X509_NAME_PTR)fv->Data;
    for (i = 0; !found && i < name->numberOfRDNs; ++i) {
      uint32_t j;
      CSSM_X509_RDN_PTR rdn = &name->RelativeDistinguishedName[i];
      for (j = 0; j < rdn->numberOfPairs; ++j) {
        CSSM_X509_TYPE_VALUE_PAIR_PTR tp = &rdn->AttributeTypeAndValue[j];
        switch (tp->valueType) {
          case BER_TAG_PRINTABLE_STRING:
          case BER_TAG_IA5_STRING:
          case BER_TAG_PKIX_UTF8_STRING:
          case BER_TAG_GENERAL_STRING:
          case BER_TAG_PKIX_UNIVERSAL_STRING:
          case BER_TAG_T61_STRING:
          case BER_TAG_VIDEOTEX_STRING:
          case BER_TAG_ISO646_STRING:
          case BER_TAG_PKIX_BMP_STRING:
            found = 1;
            break;
          default:
            /* nothing */;
        }
      }
    }
    CSSM_CL_CertAbortQuery(h, results);
    return found > 0;
  }
  if (fnc.fSecCertificateCopySubjectSummary) {
    CFStringRef summary = fnc.fSecCertificateCopySubjectSummary(cert);
    size_t len = summary ? CFStringGetLength(summary) : 0;
    if (summary) CFRelease(summary);
    return len > 0;
  }
  return false;
}

OSStatus cSecItemImport(
  CFDataRef importedData, CFStringRef fileNameOrExtension,
  SecExternalFormat *inputFormat, SecExternalItemType *itemType,
  SecItemImportExportFlags flags, const SecItemImportExportKeyParameters *keyParams,
  SecKeychainRef importKeychain, CFArrayRef *outItems)
{
  if (fnc.fSecItemImport)
    return fnc.fSecItemImport(importedData, fileNameOrExtension, inputFormat,
      itemType, flags, keyParams, importKeychain, outItems);
  else if (fnc.fSecKeychainItemImport) {
    SecKeyImportExportParameters oldKeyParams;
    SecKeyImportExportParameters *op = NULL;
    if (keyParams) {
      op = &oldKeyParams;
      memset(&oldKeyParams, 0, sizeof(oldKeyParams));
      oldKeyParams.version = keyParams->version;
      oldKeyParams.flags = keyParams->flags;
      oldKeyParams.passphrase = keyParams->passphrase;
      oldKeyParams.alertTitle = keyParams->alertTitle;
      oldKeyParams.alertPrompt = keyParams->alertPrompt;
      oldKeyParams.accessRef = keyParams->accessRef;
      /* We punt on keyUsage and keyAttributes and do not convert them */
    }
    return fnc.fSecKeychainItemImport(importedData, fileNameOrExtension, inputFormat,
      itemType, flags, op, importKeychain, outItems);
  }
  return unimpErr;
}

OSStatus cSecIdentityCreateWithCertificate(CFTypeRef k, SecCertificateRef c,
                                           SecIdentityRef *i)
{
  /* The documentation lies and this is actually present in later 10.4 versions */
  if (fnc.fSecIdentityCreateWithCertificate)
    return fnc.fSecIdentityCreateWithCertificate(k, c, i);
  return unimpErr;
}

SSLContextRef cSSLCreateContext(CFAllocatorRef a, int ps, int ct)
{
  if (fnc.fSSLCreateContext)
    return fnc.fSSLCreateContext(a, ps, ct);
  if ((ps != kSSLServerSide && ps != kSSLClientSide) || (ct != kSSLStreamType))
    return NULL;
  if (fnc.fSSLNewContext && fnc.fSSLDisposeContext) {
    SSLContextRef cxt;
    OSStatus err = fnc.fSSLNewContext(ps == kSSLServerSide, &cxt);
    return err ? NULL : cxt;
  }
  return NULL;
}

void cSSLDisposeContext(SSLContextRef c)
{
  if (fnc.fSSLCreateContext)
    CFRelease(c);
  else if (fnc.fSSLDisposeContext)
    fnc.fSSLDisposeContext(c);
}

#elif TARGET_OS_EMBEDDED || TARGET_OS_IPHONE

#error iOS is not currently supported

#endif /* TARGET_OS_EMBEDDED || TARGET_OS_IPHONE */
