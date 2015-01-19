/*

stcompat.c -- SecureTransport compatibility implementation
Copyright (C) 2014,2015 Kyle J. McKay.  All rights reserved.

If this software is included as part of a build of
the cURL library, it may be used under the same license
terms as the cURL library.

Otherwise the GPLv2 license applies, see
  http://www.gnu.org/licenses/gpl-2.0-standalone.html

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

*/

#undef sprintf
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
#include <arpa/inet.h>
#include <pwd.h>
#include <crt_externs.h>
#include "stcompat.h"

#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))
#include <dlfcn.h>
__attribute__((constructor,used)) static void stcompat_initialize(void);
#endif /* (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)) */

typedef struct data_s {
  const uint8_t *d;
  size_t l;
} data_t;

extern CFStringRef CFStringCreateWithBytesNoCopy(
  CFAllocatorRef alloc,
  const UInt8 *bytes,
  CFIndex numBytes,
  CFStringEncoding encoding,
  Boolean isExternalRepresentation,
  CFAllocatorRef contentsDeallocator); /* available 10.4 but not in header */
extern CFStringRef NSTemporaryDirectory(void);
static Boolean CheckPubKeyOkayInt(CFDataRef d, data_t *pubkey, int flags);

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

char *CFStringCreateUTF8String(CFStringRef s, Boolean release)
{
  size_t m;
  char *c;

  if (!s) return NULL;
  m = (size_t)CFStringGetMaximumSizeForEncoding(
    CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
  c = (char *)malloc(m);
  if (!c) {
    if (release) CFRelease(s);
    return NULL;
  }
  if (!CFStringGetCString(s, c, m, kCFStringEncodingUTF8)) {
    free(c);
    c = NULL;
  }
  if (release) CFRelease(s);
  return c;
}

static CFStringRef MakeVisibleString(CFStringRef in)
{
  CFStringRef nullbyte;
  CFMutableStringRef m;
  if (!in) return in;
  nullbyte = CFStringCreateWithBytesNoCopy(kCFAllocatorDefault, (UInt8 *)"\0",
    1, kCFStringEncodingASCII, false, kCFAllocatorNull);
  if (!nullbyte) return in;
  m = CFStringCreateMutableCopy(kCFAllocatorDefault, 0, in);
  if (!m) return in;
  CFRelease(in);
  CFStringFindAndReplace(m, nullbyte, CFSTR("\\000"),
    CFRangeMake(0, CFStringGetLength(m)), 0);
  CFRelease(nullbyte);
  return m;
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

#undef memmem
#define memmem(v1,l1,v2,l2) cmemmem(v1,l1,v2,l2)
static void *cmemmem(const void *_m, size_t ml, const void *_s, size_t sl)
{
  const char *m = (const char *)_m;
  const char *s = (const char *)_s;
  if (!ml || !sl || ml < sl) return NULL;
  if (sl == 1) return memchr(m, *s, ml);
  if (ml == sl) return (void *)(memcmp(m, s, sl) ? NULL : m);
  do {
    size_t o;
    const char *p = memchr(m, *s, ml);
    if (!p) return NULL;
    o = p - m;
    ml -= o;
    m += o;
    if (ml < sl) return NULL;
    if (!memcmp(m, s, sl)) return (void *)m;
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
    const char *p = (char *)memmem(m, l, marker, mkl);
    if (!p) return NULL;
    l -= (p - m) + mkl;
    m = p + mkl;
    if (p > origm && !is_eol(p[-1])) continue;
    t = (char *)memmem(m, l, "-----", 5);
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

typedef enum pemtype_e {
  pemtype_unknown,
  pemtype_certificate, /* "CERTIFICATE" or "TRUSTED CERTIFICATE" */
  pemtype_publickey, /* "PUBLIC KEY" */
  pemtype_privatekey_rsa /* "RSA PRIVATE KEY" */
} pemtype_t;

typedef struct peminfo_s {
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
  } else if (begtype == 10 && !memcmp(beg + 11, "PUBLIC KEY", 10)) {
    o->type = pemtype_publickey;
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
      CFDataRef der = CFDataCreate(kCFAllocatorDefault, (UInt8 *)certs, certslen);
      if (!der) {
        CFRelease(a);
        return NULL;
      }
      cert = createvalidcert(der);
      CFRelease(der);
      if (!cert) {
        if (e)
          e->f(e->u, "Invalid CA certificate bad DER data");
        CFRelease(a);
        return NULL;
      }
      CFArrayAppendValue(a, cert);
      CFRelease(cert);
      return a;
    } else if (readcnt == -1) {
      if (e)
        e->f(e->u, "Invalid CA certificate #%u (offset %u) in bundle",
                   (unsigned)cnt, (unsigned)(p-certs));
      CFRelease(a);
      return NULL;
    } else if (readcnt && pem.type == pemtype_certificate) {
      CFDataRef der = CFDataCreateFromBase64(kCFAllocatorDefault, pem.body, pem.bodylen);
      SecCertificateRef cert;
      if (!der) {
        if (e)
          e->f(e->u, "Invalid CA certificate #%u (offset %u) bad base 64 in bundle",
                     (unsigned)cnt, (unsigned)(pem.start-certs));
        CFRelease(a);
        return NULL;
      }
      cert = createvalidcert(der);
      CFRelease(der);
      if (!cert) {
        if (e)
          e->f(e->u, "Invalid CA certificate #%u (offset %u) bad cert data in bundle",
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
  if (!CFArrayGetCount(a)) {
    CFRelease(a);
    a = NULL;
  }
  return a;
}

static void CFArrayAppendValue_data(CFMutableArrayRef a, const data_t *d)
{
  if (d && d->d && d->l) {
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, (UInt8 *)d->d, d->l);
    if (data) {
      CFArrayAppendValue(a, data);
      CFRelease(data);
    }
  }
}

CFArrayRef CreatePubKeyArrayWithData(CFDataRef d, const errinfo_t *e)
{
  const char *keys, *p;
  size_t keyslen, plen, cnt = 1;
  CFMutableArrayRef a;
  if (!d) return NULL;
  keys = (char *)CFDataGetBytePtr(d);
  keyslen = (size_t)CFDataGetLength(d);
  a = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  if (!a) return NULL;
  p = keys;
  plen = keyslen;
  while (plen) {
    peminfo_t pem;
    data_t pubkey;
    int readcnt = nextpem(p, plen, &pem);
    if (!readcnt && p == keys) {
      /* assume it's a DER public key */
      CFDataRef der = CFDataCreate(kCFAllocatorDefault, (UInt8 *)keys, keyslen);
      if (!der) {
        CFRelease(a);
        return NULL;
      }
      if (!CheckPubKeyOkayInt(der, &pubkey, 0x01)) {
        CFRelease(der);
        if (e)
          e->f(e->u, "Invalid public key bad DER data");
        CFRelease(a);
        return NULL;
      }
      CFArrayAppendValue_data(a, &pubkey);
      CFRelease(der);
      return a;
    } else if (readcnt == -1) {
      if (e)
        e->f(e->u, "Invalid public key #%u (offset %u) in bundle",
                   (unsigned)cnt, (unsigned)(p-keys));
      CFRelease(a);
      return NULL;
    } else if (readcnt && (pem.type == pemtype_publickey ||
                           pem.type == pemtype_certificate)) {
      CFDataRef der = CFDataCreateFromBase64(kCFAllocatorDefault, pem.body, pem.bodylen);
      if (!der) {
        if (e)
          e->f(e->u, "Invalid public key #%u (offset %u) bad base 64 in bundle",
                     (unsigned)cnt, (unsigned)(pem.start-keys));
        CFRelease(a);
        return NULL;
      }
      if (!CheckPubKeyOkayInt(der, &pubkey, 0x01)) {
        CFRelease(der);
        if (e)
          e->f(e->u, "Invalid public key #%u (offset %u) bad public key data in bundle",
                     (unsigned)cnt, (unsigned)(pem.start-keys));
        CFRelease(a);
        return NULL;
      }
      CFArrayAppendValue_data(a, &pubkey);
      CFRelease(der);
      ++cnt;
    } else if (!readcnt) break;
    plen -= (pem.start + pem.len) - p;
    p = pem.start + pem.len;
  }
  if (!CFArrayGetCount(a)) {
    CFRelease(a);
    a = NULL;
  }
  return a;
}

typedef struct homedirs_s {
  /* note that we use geteuid and not getuid because any created files will
   * end up being owned by geteuid and therefore using geteuid()'s HOME wil
   * end up being the least disruptive and also if geteuid() != getuid() then
   * we probably can't read getuid()'s HOME anyway so that's a guaranteed fail */
  char *home; /* "HOME=..." from getpwuid(geteuid()) if different from environ */
  char *cur_home; /* "HOME=..." as found in environ if home set otherwise NULL */
} homedirs_t;

static char *find_home_env(void)
{
  char ***eptr = _NSGetEnviron();
  char **ptr;
  if (!eptr) return NULL;
  ptr = *eptr;
  while (*ptr && strncmp(*ptr, "HOME=", 5)) {
    ++ptr;
  }
  return *ptr ? *ptr : NULL;
}

static void get_home_dirs(homedirs_t *dirs)
{
  struct passwd *pwinf;

  if (!dirs) return;
  dirs->home = NULL;
  dirs->cur_home = find_home_env();
  pwinf = getpwuid(geteuid());
  if (pwinf && pwinf->pw_dir &&
      (!dirs->cur_home || strcmp(dirs->cur_home+5, pwinf->pw_dir)))
    asprintf(&dirs->home, "HOME=%s", pwinf->pw_dir);
  if (!dirs->home)
    dirs->cur_home = NULL;
}

static void free_home_dirs(homedirs_t *dirs)
{
  if (dirs)
    free(dirs->home);
}

typedef struct tempch_s {
  SecKeychainRef ref;
  homedirs_t dirs;
  char pw[16]; /* random 15-character (0x20-0x7e), NULL terminated password */
  char loc[1]; /* Always will have at least a NULL byte */
} tempch_t;

static void gen_rand_pw(void *_out, size_t len)
{
  unsigned char *out = (unsigned char *)_out;
  int fd;
  if (!out || !len) return;
  fd = open("/dev/random", O_RDONLY);
  if (fd) {
    do {
      ssize_t cnt, i;
      do {
        cnt = read(fd, out, len);
      } while (cnt == -1 && errno == EINTR);
      if (cnt <= 0) return;
      for (i = 0; i < cnt; ++i) {
        out[i] = (unsigned char)((((unsigned)out[i] * 95) >> 8) + 32);
      }
      len -= (size_t)cnt;
    } while (len);
    close(fd);
  }
}

static tempch_t *new_temp_keych(void)
{
  tempch_t *ans;
  char newdir[PATH_MAX];
  Boolean okay;
  CFStringRef tempdir = CFCopyTemporaryDirectory();

  if (!tempdir) return NULL;
  okay = CFStringGetCString(tempdir, newdir, sizeof(newdir) - 32, kCFStringEncodingUTF8);
  CFRelease(tempdir);
  if (!okay) return NULL;
  strcat(newdir, "/tch.XXXXXX");
  ans = (tempch_t *)malloc(sizeof(tempch_t) + strlen(newdir) + 14 /* "/temp.keychain" */);
  if (!ans) return NULL;
  ans->ref = NULL;
  strcpy(ans->loc, newdir);
  strlcpy(ans->pw, "(:vCZ\"t{UA-zl3g", sizeof(ans->pw)); /* fallback if random fails */
  gen_rand_pw(ans->pw, sizeof(ans->pw)-1);
  ans->pw[sizeof(ans->pw)-1] = '\0';
  if (!mkdtemp(ans->loc)) {
    free(ans);
    return NULL;
  }
  strcat(ans->loc, "/temp.keychain");
  get_home_dirs(&ans->dirs);
  return ans;
}

static void del_temp_keych(tempch_t *keych)
{
  size_t l;
  if (!keych) return;
  l = strlen(keych->loc);
  if (l > 14 && !strcmp(keych->loc + (l - 14), "/temp.keychain")) {
    DIR *d;
    if (keych->ref) {
      int needs_reset = 0;
      if (keych->dirs.home) {
        keych->dirs.cur_home = find_home_env();
        if (!keych->dirs.cur_home || strcmp(keych->dirs.cur_home, keych->dirs.home)) {
          needs_reset = 1;
          putenv(keych->dirs.home);
        }
      }
      (void)SecKeychainLock(keych->ref);
      (void)SecKeychainDelete(keych->ref);
      if (needs_reset) {
        if (keych->dirs.cur_home)
          putenv(keych->dirs.cur_home);
        else
          unsetenv("HOME");
      }
      CFRelease(keych->ref);
      keych->ref = NULL;
    }
    unlink(keych->loc);
    keych->loc[l - 14] = '\0';
    /* the keychain code may leave dot, possibly comma and yet other turds
     * we may have to remove */
    d = opendir(keych->loc);
    if (d) {
      struct dirent *ent;
      while ((ent=readdir(d)) != NULL) {
        char turd[PATH_MAX];
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0'
             || (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) continue;
        snprintf(turd, sizeof(turd), "%s/%s", keych->loc, ent->d_name);
        unlink(turd);
      }
      closedir(d);
    }
    rmdir(keych->loc);
    free_home_dirs(&keych->dirs);
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
  SecCertificateRef cert, CFDataRef keydata, CFTypeRef pw, CFStringRef hint,
  void **kh)
{
  int ispem = 0;
  CFDataRef rawkey = NULL;
  tempch_t *keych = NULL;
  int err;
  SecKeychainRef keychain = NULL;
  SecExternalFormat format;
  SecExternalItemType type;
  SecItemImportExportKeyParameters params;
  CFArrayRef items = NULL;
  SecKeyRef key = NULL;
  SecIdentityRef ans = NULL;

  if (!cert || !kh) return NULL;
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
     * private key we're importing be searchable by default in other apps.
     * If we are running with HOME != ~geteuid() then we likely have no
     * ~/Library/Preferences/com.apple.security.plist which means the system
     * will "helpfully" set the default keychain to this new keychain we've
     * just created which is very bad.  If Xcode is running it will listen
     * to that event and then call SecKeychainSetDefault with that very
     * same temporary keychain (I have no idea why it does this stupid thing)
     * and that will make it permanent for the user.  Ugh.  To avoid this,
     * we temporarily set HOME to getpwuid(geteuid())->pw_dir while we are
     * creating the temporary keychain and then put HOME back the way it was
     * immediately thereafter.  Git likes to run tests with HOME set to
     * alternate locations so it's prudent to handle this. */
    if (keych->dirs.home)
      putenv(keych->dirs.home);
    err = SecKeychainCopySearchList(&searchlist);
    if (!err && searchlist)
      err = SecKeychainCreate(keych->loc, sizeof(keych->pw), keych->pw, false,
                              NULL, &keychain);
    if (searchlist) {
      if (!err)
        err = SecKeychainSetSearchList(searchlist);
      CFRelease(searchlist);
    }
    if (keych->dirs.home) {
      if (keych->dirs.cur_home)
        putenv(keych->dirs.cur_home);
      else
        unsetenv("HOME");
    }
    if (err || !keychain)
      break;
    keych->ref = keychain;
    err = SecKeychainUnlock(keychain, sizeof(keych->pw), keych->pw, true);
    if (err) break;
    {
      SecKeychainSettings settings;
      settings.version = SEC_KEYCHAIN_SETTINGS_VERS1;
      settings.lockOnSleep = false;
      settings.useLockInterval = false;
      settings.lockInterval = INT_MAX;
      (void)SecKeychainSetSettings(keychain, &settings);
    }
    format = ispem ? kSecFormatWrappedOpenSSL : kSecFormatOpenSSL;
    type = kSecItemTypePrivateKey;
    memset(&params, 0, sizeof(params));
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = kSecKeyImportOnlyOne|kSecKeyNoAccessControl;
    if (pw)
      params.passphrase = pw;
    else {
      params.flags |= kSecKeySecurePassphrase;
      /* Note that params.alertTitle is ignored */
      params.alertPrompt = hint;
    }
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
    /* If we have a key we must also have a keychain */
    err = cSecIdentityCreateWithCertificate(keychain, cert, &ans);
    CFRelease(key);
  }
  /* We MUST NOT call SecKeychainDelete because that will purge all copies of
   * the keychain from memory.  We've already removed it from the search list
   * so we just release it and remove the disk files instead in order to allow
   * the in memory copy to remain unmolested.  Unfortunately on older systems
   * this is not good enough, so we have to leave the keychain itself around. */
  if (!ans && keych) {
    del_temp_keych(keych);
    keych = NULL;
  }
  if (!ans && (!rawkey || (!ispem && !key))) {
    /* Try again with the default keychain list, but only if a key was not
     * provided or was provided in non-PEM and we failed to import it. */
    err = cSecIdentityCreateWithCertificate(NULL, cert, &ans);
  }
  if (ans)
    *kh = keych;
  else
    del_temp_keych(keych);
  return ans;
}

void DisposeIdentityKeychainHandle(void *ch)
{
  del_temp_keych((tempch_t *)ch);
}

CFArrayRef CreateClientAuthWithCertificatesAndKeyData(CFArrayRef certs,
                                    CFDataRef keydata, CFTypeRef pw,
                                    CFStringRef hint, void **kh)
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
  identity = cSecIdentityCreateWithCertificateAndKeyData(cert, keydata, pw,
                                                         hint, kh);
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

typedef struct {
  size_t Length;
  uint8_t *Data;
} cCSSM_DATA;

static struct {
  OSStatus (*fSSLSetTrustedRoots)(SSLContextRef, CFArrayRef, Boolean);
  OSStatus (*fSSLGetPeerSecTrust)(SSLContextRef, SecTrustRef *);
  OSStatus (*fSSLCopyPeerTrust)(SSLContextRef, SecTrustRef *);
  OSStatus (*fSecTrustGetResult)(SecTrustRef, SecTrustResultType *,
                                 CFArrayRef *, CSSM_TP_APPLE_EVIDENCE_INFO **);
  OSStatus (*fSecTrustSetAnchorCertificatesOnly)(SecTrustRef, Boolean);
  OSStatus (*fSSLGetPeerCertificates)(SSLContextRef cxt, CFArrayRef *certs);
  OSStatus (*fSSLCopyPeerCertificates)(SSLContextRef cxt, CFArrayRef *certs);
  OSStatus (*fSSLSetProtocolVersionEnabled)(SSLContextRef cxt, SmallEnum, Boolean);
  OSStatus (*fSSLSetProtocolVersionMin)(SSLContextRef cxt, SmallEnum);
  OSStatus (*fSSLSetProtocolVersionMax)(SSLContextRef cxt, SmallEnum);
  OSStatus (*fSSLSetSessionOption)(SSLContextRef, SmallEnum, Boolean);
  SecCertificateRef (*fSecCertificateCreateWithData)(CFAllocatorRef, CFDataRef);
  OSStatus (*fSecCertificateCreateFromData)(const cCSSM_DATA *, CSSM_CERT_TYPE,
                                      CSSM_CERT_ENCODING, SecCertificateRef *);
  OSStatus (*fSecCertificateGetData)(SecCertificateRef, cCSSM_DATA *);
  CFDataRef (*fSecCertificateCopyData)(SecCertificateRef);
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
  LOOKUP(SSLGetPeerSecTrust);
  LOOKUP(SSLCopyPeerTrust);
  LOOKUP(SecTrustGetResult);
  LOOKUP(SecTrustSetAnchorCertificatesOnly);
  LOOKUP(SSLGetPeerCertificates);
  LOOKUP(SSLCopyPeerCertificates);
  LOOKUP(SSLSetProtocolVersionEnabled);
  LOOKUP(SSLSetProtocolVersionMin);
  LOOKUP(SSLSetProtocolVersionMax);
  LOOKUP(SSLSetSessionOption);
  LOOKUP(SecCertificateCreateWithData);
  LOOKUP(SecCertificateCreateFromData);
  LOOKUP(SecCertificateGetData);
  LOOKUP(SecCertificateCopyData);
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

OSStatus cSSLCopyPeerTrust(SSLContextRef cxt, SecTrustRef *trust)
{
  if (fnc.fSSLCopyPeerTrust)
    return fnc.fSSLCopyPeerTrust(cxt, trust);
  if (fnc.fSSLGetPeerSecTrust) {
    OSStatus err = fnc.fSSLGetPeerSecTrust(cxt, trust);
    if (!err) CFRetain(*trust);
    return err;
  }
  return unimpErr;
}

OSStatus cSecTrustGetResult(SecTrustRef trust, SecTrustResultType *result,
              CFArrayRef *certChain, CSSM_TP_APPLE_EVIDENCE_INFO **statusChain)
{
  if (fnc.fSecTrustGetResult)
    return fnc.fSecTrustGetResult(trust, result, certChain, statusChain);
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

OSStatus cSecTrustSetAnchorCertificatesOnly(SecTrustRef cxt, Boolean anchorsOnly)
{
  if (fnc.fSecTrustSetAnchorCertificatesOnly)
    return fnc.fSecTrustSetAnchorCertificatesOnly(cxt, anchorsOnly);
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
    cCSSM_DATA certdata;
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

CFDataRef cSecCertificateCopyData(SecCertificateRef c)
{
  if (!c) return NULL;
  if (CFGetTypeID(c) != SecCertificateGetTypeID()) return NULL;
  if (fnc.fSecCertificateCopyData)
    return fnc.fSecCertificateCopyData(c);
  if (fnc.fSecCertificateGetData) {
    cCSSM_DATA certdata;
    OSStatus err = fnc.fSecCertificateGetData(c, &certdata);
    if (err || !certdata.Data || !certdata.Length) return NULL;
    return CFDataCreate(kCFAllocatorDefault, certdata.Data, certdata.Length);
  }
  return NULL;
}

Boolean BlobsEqual(CFDataRef d1, CFDataRef d2)
{
  size_t l1, l2;
  Boolean ans = false;

  if (!d1 || !d2)
    return false;
  l1 = CFDataGetLength(d1);
  l2 = CFDataGetLength(d2);
  if (l1 == l2) {
    const void *p1 = (void *)CFDataGetBytePtr(d1);
    const void *p2 = (void *)CFDataGetBytePtr(d2);
    ans = memcmp(p1, p2, l1) == 0;
  }
  return ans;
}

Boolean SecCertsEqual(SecCertificateRef c1, SecCertificateRef c2)
{
  CFDataRef d1, d2;
  Boolean ans = false;
  d1 = cSecCertificateCopyData(c1);
  if (!d1) return false;
  d2 = cSecCertificateCopyData(c2);
  if (!d2) {
    CFRelease(d1);
    return false;
  }
  ans = BlobsEqual(d1, d2);
  CFRelease(d1);
  CFRelease(d2);
  return ans;
}

Boolean BlobInArray(CFDataRef d, CFArrayRef a)
{
  size_t i, cnt;
  if (!d || !a || !CFArrayGetCount(a)) return false;
  cnt = CFArrayGetCount(a);
  for (i = 0; i < cnt; ++i) {
    if (BlobsEqual(d, (CFDataRef)CFArrayGetValueAtIndex(a, i)))
      return true;
  }
  return false;
}

Boolean SecCertInArray(SecCertificateRef c, CFArrayRef a)
{
  size_t i, cnt;
  if (!c || !a || !CFArrayGetCount(a)) return false;
  cnt = CFArrayGetCount(a);
  for (i = 0; i < cnt; ++i) {
    if (SecCertsEqual(c, (SecCertificateRef)CFArrayGetValueAtIndex(a, i)))
      return true;
  }
  return false;
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

CF_INLINE bool is_ldh(int c)
{
  return
    ('A' <= c && c <= 'Z') ||
    ('a' <= c && c <= 'z') ||
    ('0' <= c && c <= '9') ||
    c == '-';
}

CF_INLINE size_t get_label_len(const char *p, size_t l)
{
  size_t ans = 0;
  while (l-- && is_ldh(*p++)) ++ans;
  return ans;
}

static bool is_dns_name(const void *_p, size_t l, bool wcok)
{
  const char *p = (char *)_p;
  size_t idx = 0;

  if (!p) return false;
  if (l >= 1 && p[l-1] == '.') --l;
  if (!l) return false;
  if (l > 255) return false;
  do {
    size_t lablen = get_label_len(p, l);
    if (lablen > 63) return false;
    if (!idx && !lablen && wcok && l >= 2 && p[0] == '*' && p[1] == '.') lablen=1;
    if (!lablen) return false;
    if (p[0] == '-' || p[lablen - 1] == '-') return false;
    if (lablen < l) {
      if (p[lablen] != '.') return false;
      ++lablen;
    }
    l -= lablen;
    p += lablen;
    ++idx;
  } while (l);
  return true;
}

CF_INLINE char clc(char c)
{
  return 'A' <= c && c <= 'Z' ? c - 'A' + 'a' : c;
}

CF_INLINE bool matchicase(const char *p1, const char *p2, size_t l)
{
  while (l--) {
    if (clc(*p1++) != clc(*p2++)) return false;
  }
  return true;
}

static bool peername_matches_id(const char *peername, CFDataRef idrawname)
{
  size_t pl, il, idx;
  const char *idname;
  if (!peername || !idrawname) return false;
  idname = (const char *)CFDataGetBytePtr(idrawname);
  if (!idname) return false;
  pl = strlen(peername);
  il = (size_t)CFDataGetLength(idrawname);
  if (!is_dns_name(peername, pl, false) || !is_dns_name(idname, il, true))
    return false;
  idx = 0;
  if (peername[pl - 1] == '.') --pl;
  if (idname[il - 1] == '.') --il;
  if (pl > 255 || il > 255)
    return false;
  while (pl && il) {
    size_t pll = get_label_len(peername, pl);
    size_t ill = get_label_len(idname, il);
    if (!idx && !ill && il >= 2 && idname[0] == '*' && idname[1] == '.') ill=1;
    if (pll < pl) {
      if (peername[pll] != '.') return false;
      ++pll;
    }
    if (ill < il) {
      if (idname[ill] != '.') return false;
      ++ill;
    }
    if (idx || idname[0] != '*') {
      if (pll != ill) return false;
      if (!matchicase(peername, idname, pll)) return false;
    }
    peername += pll;
    pl -= pll;
    idname += ill;
    il -= ill;
    ++idx;
  }
  return !pl && !il;
}

CF_INLINE size_t get_num_len(const char *p, size_t l)
{
  size_t ans = 0;
  while (l-- && '0' <= *p && *p <= '9') {
    ++ans;
    ++p;
  }
  return ans;
}

Boolean IsIPv4Name(const void *_p, size_t l)
{
  const char *p = (char *)_p;
  size_t idx = 0;

  if (!p || l < 7) return false;
  do {
    size_t lablen;
    if (++idx > 4) return false;
    lablen = get_num_len(p, l);
    if (lablen > 3) return false;
    if (lablen >= 2 && *p == '0') return false;
    else if (lablen == 3) {
      if (*p >= '3') return false;
      if (*p == '2') {
        if (p[1] >= '6') return false;
        if (p[1] == '5' && p[2] > '5') return false;
      }
    }
    if (lablen < l) {
      if (p[lablen] != '.') return false;
      ++lablen;
    }
    l -= lablen;
    p += lablen;
  } while (l);
  return idx == 4;
}

static bool parse_ipv4_name(const void *_p, size_t l, uint8_t ipv4[4])
{
  unsigned short s[4];
  char ipv4str[16];
  const char *p = (char *)_p;
  if (!IsIPv4Name(p, l) || l > 15) return false;
  memcpy(ipv4str, p, l);
  ipv4str[l] = 0;
  if (sscanf(ipv4str, "%hu.%hu.%hu.%hu", s, s+1, s+2, s+3) == 4) {
    ipv4[0] = (uint8_t)s[0];
    ipv4[1] = (uint8_t)s[1];
    ipv4[2] = (uint8_t)s[2];
    ipv4[3] = (uint8_t)s[3];
    return true;
  }
  return false;
}

static bool parse_ipv6_name(const void *_p, size_t l, uint8_t ipv6[16])
{
  char ipv6str[INET6_ADDRSTRLEN];
  const char *p = (char *)_p;
  const char *pct;
  if (!p) return false;
  if (l >= 1 && p[0] == '[') {
    ++p;
    --l;
  }
  if (l >= 1 && p[l-1] == ']') --l;
  pct = (char *)(l ? memchr(p, '%', l) : NULL);
  if (pct) l = pct - p;
  if (l < 3 || l >= INET6_ADDRSTRLEN) return false;
  memcpy(ipv6str, p, l);
  ipv6str[l] = 0;
  return inet_pton(AF_INET6, ipv6str, ipv6) == 1;
}

#define U(x) ((const uint8_t *)(x))
static const data_t OID_BasicConstraints = {U("\006\003\125\035\023"), 5};
static const data_t OID_SubjectAltName = {U("\006\003\125\035\021"), 5};
static const data_t OID_SubjectKeyIdentifier = {U("\006\003\125\035\016"), 5};
static const data_t OID_AuthorityKeyIdentifier = {U("\006\003\125\035\043"), 5};
static const data_t OID_CommonName = {U("\006\003\125\004\003"), 5};
#undef U

typedef struct der_atom_s {
  uint8_t clas; /* 0, 1, 2, or 3 */
  uint8_t cons; /* 0 or 1 */
  uint8_t rawtag; /* raw value of first byte of tag */
  uint32_t tag; /* tag value */
  size_t hl; /* length of header excluding actual data */
  size_t dl; /* length of actual data */
} der_atom_t;

typedef struct der_cert_s {
  uint8_t vers; /* 0 => v1, 1 => v2, 2 => v3 */
  uint8_t caFlag; /* 0 unless basic constraints present then 0x80=critial 0x01=value */
  uint8_t isCA; /* true if caFlag==0x81 or subject==issuer && vers < 2 */
  uint8_t isRoot; /* true if isCA and subject == issuer */
  char notBefore[16]; /* Not before date either 13 chars or 15 chars plus Nul */
  char notAfter[16];  /* Not after date see notBefore for format */
  data_t subject; /* points to sequence */
  data_t subjectPubKey; /* points to subjectPublicKeyInfo sequence */
  data_t subjectAltNames; /* null unless v3 extension present, points to sequence */
  data_t subjectKeyId; /* null unless v3 extension present, points to raw bytes */
  data_t issuer; /* points to sequence */
  data_t issuerKeyId; /* null unless v3 extension present, points to raw bytes */
} der_cert_t;

static bool read_der_atom(const data_t *d, der_atom_t *o)
{
  uint8_t byte;
  uint32_t tag;
  size_t pos, len;
  if (!d || !d->d || !d->l || !o) return false;
  o->clas = (*d->d >> 6) & 0x3;
  o->cons = (*d->d >> 5) & 0x1;
  o->rawtag = *d->d;
  tag = *d->d & 0x1f;
  pos = 1;
  if (tag == 0x1f) {
    tag = 0;
    do {
      if (pos >= d->l) return false;
      tag <<= 7;
      byte = d->d[pos++];
      tag |= byte & 0x7f;
    } while (byte & 0x80);
  }
  o->tag = tag;
  if (pos >= d->l) return false;
  byte = d->d[pos++];
  if (byte & 0x80) {
    unsigned cnt = byte & 0x7f;
    if (!cnt || pos + cnt > d->l) return false;
    len = 0;
    do {
      len <<= 8;
      len |= d->d[pos++];
    } while (--cnt);
  } else {
    len = byte;
  }
  if (pos + len > d->l) return false;
  o->hl = pos;
  o->dl = len;
  return true;
}

/* return true if _d->d points at a valid DER atom that is _d->l bytes long
 * or less.  If exact_length_match_only is set the DER atom MUST be exactly
 * _d->l bytes long.  If the atom at _d->d is a set or sequence, then its
 * elements are also examined recursively to make sure they are also valid. */
static bool is_der(const data_t *_d, bool exact_length_match_only)
{
  bool first = true;
  data_t d;
  if (!_d || !_d->d || !_d->l) return false;
  d.d = _d->d;
  d.l = _d->l;
  do {
    der_atom_t atom;
    if (!read_der_atom(&d, &atom)) return false;
    d.l -= atom.hl;
    d.d += atom.hl;
    if ((atom.rawtag & 0xfe) != 0x30) {
      d.l -= atom.dl;
      d.d += atom.dl;
      if (first) break;
    } else if (first) {
      d.l = atom.dl;
    }
    first = false;
  } while (d.l);
  return !d.l && (d.d == _d->d + _d->l || !exact_length_match_only);
}

/* true is returned if data is not NULL and matches:
 * SEQUENCE {
 *   SEQUENCE {
 *      OBJECT ID,
 *      optional...
 *   },
 *   BIT STRING {
 *      whatever...
 *   },
 * } == length of data
 */
static bool check_der_pubkey(const data_t *_d)
{
  data_t d;
  der_atom_t atom;

  if (!_d || !_d->d || !_d->l) return false;
  if (!is_der(_d, true)) return false;
  d.d = _d->d;
  d.l = _d->l;
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x30) return false;
  d.l = atom.dl;
  d.d += atom.hl;
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x30) return false;
  if (!atom.dl || d.d[atom.hl] != 0x06) return false;
  d.l -= atom.hl + atom.dl;
  d.d += atom.hl + atom.dl;
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x03) return false;
  return true;
}

static int data_matches(const data_t *o1, const data_t *o2)
{
  if (!o1 || !o2 || !o1->l || !o2->l || o1->l != o2->l)
    return 0;
  return memcmp(o1->d, o2->d, o1->l) == 0;
}

static bool read_der_cert(const data_t *_d, der_cert_t *o)
{
  data_t d;
  der_atom_t atom;

  if (!_d || !_d->d || !_d->l || !o) return false;
  if (!is_der(_d, true)) return false;
  d.d = _d->d;
  d.l = _d->l;
  memset(o, 0, sizeof(*o));
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x30) return false;
  d.l = atom.dl;
  d.d += atom.hl;
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x30) return false;
  d.l = atom.dl;
  d.d += atom.hl;
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag == 0xA0) {
    d.l -= atom.hl;
    d.d += atom.hl;
    if (atom.dl != 3 || d.d[0] != 2 || d.d[1] != 1) return false;
    o->vers = d.d[2]; /* not validated */
    d.l -= atom.dl;
    d.d += atom.dl;
    if (!read_der_atom(&d, &atom)) return false;
  } else {
    o->vers = 0; /* implied v1 */
  }
  if (atom.rawtag != 2) return false;
  /* skip serialNumber */
  d.l -= atom.hl + atom.dl;
  d.d += atom.hl + atom.dl;
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x30) return false;
  /* skip signature */
  d.l -= atom.hl + atom.dl;
  d.d += atom.hl + atom.dl;
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x30) return false;
  o->issuer.d = d.d;
  o->issuer.l = atom.hl + atom.dl;
  d.l -= atom.hl + atom.dl;
  d.d += atom.hl + atom.dl;
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x30) return false;
  {
    /* parse validity */
    data_t vdate;
    vdate.d = d.d + atom.hl;
    vdate.l = atom.dl;
    d.l -= atom.hl + atom.dl;
    d.d += atom.hl + atom.dl;
    if (!read_der_atom(&vdate, &atom)) return false;
    if (atom.rawtag != 0x17 && atom.rawtag != 0x18) return false;
    if (atom.rawtag == 0x17 && atom.dl != 13) return false;
    if (atom.rawtag == 0x18 && atom.dl != 15) return false;
    memcpy(o->notBefore, vdate.d + atom.hl, atom.dl);
    vdate.l += atom.hl + atom.dl;
    vdate.d += atom.hl + atom.dl;
    if (!read_der_atom(&vdate, &atom)) return false;
    if (atom.rawtag != 0x17 && atom.rawtag != 0x18) return false;
    if (atom.rawtag == 0x17 && atom.dl != 13) return false;
    if (atom.rawtag == 0x18 && atom.dl != 15) return false;
    memcpy(o->notAfter, vdate.d + atom.hl, atom.dl);
    if (vdate.d + atom.hl + atom.dl != d.d) return false;
  }
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x30) return false;
  o->subject.d = d.d;
  o->subject.l = atom.hl + atom.dl;
  d.l -= atom.hl + atom.dl;
  d.d += atom.hl + atom.dl;
  if (!read_der_atom(&d, &atom)) return false;
  if (atom.rawtag != 0x30) return false;
  o->subjectPubKey.d = d.d;
  o->subjectPubKey.l = atom.hl + atom.dl;
  if (!check_der_pubkey(&o->subjectPubKey)) return false;
  d.l -= atom.hl + atom.dl;
  d.d += atom.hl + atom.dl;
  do {
    if (o->vers != 2 || !d.l) break;
    if (!read_der_atom(&d, &atom)) return false;
    if (atom.rawtag == 0x81) {
      /* skip issuerUniqueID */
      d.l -= atom.hl + atom.dl;
      d.d += atom.hl + atom.dl;
      if (!d.l) break;
      if (!read_der_atom(&d, &atom)) return false;
    }
    if (atom.rawtag == 0x82) {
      /* skip subjectUniqueID */
      d.l -= atom.hl + atom.dl;
      d.d += atom.hl + atom.dl;
      if (!d.l) break;
      if (!read_der_atom(&d, &atom)) return false;
    }
    if (atom.rawtag != 0xA3) return false;
    /* found v3 extensions */
    d.l = atom.dl;
    d.d += atom.hl;
    if (!read_der_atom(&d, &atom)) return false;
    if (atom.rawtag != 0x30) return false;
    d.l -= atom.hl;
    d.d += atom.hl;
    do {
      uint8_t crit = 0;
      data_t oid, value;
      if (!read_der_atom(&d, &atom)) return false;
      if (atom.rawtag != 0x30) return false;
      d.l -= atom.hl;
      d.d += atom.hl;
      if (!read_der_atom(&d, &atom)) return false;
      if (atom.rawtag != 6) return false;
      oid.d = d.d;
      oid.l = atom.hl + atom.dl;
      d.l -= atom.hl + atom.dl;
      d.d += atom.hl + atom.dl;
      if (!read_der_atom(&d, &atom)) return false;
      if (atom.rawtag == 1) {
        /* skip over boolean but record its value */
        if (atom.dl != 1) return false;
        crit = *(d.d + atom.hl);
        d.l -= atom.hl + atom.dl;
        d.d += atom.hl + atom.dl;
        if (!read_der_atom(&d, &atom)) return false;
      }
      if (atom.rawtag != 4) return false;
      d.l -= atom.hl;
      d.d += atom.hl;
      value.d = d.d;
      value.l = atom.dl;
      d.l -= atom.dl;
      d.d += atom.dl;
      if (data_matches(&oid, &OID_BasicConstraints)) {
        if (!read_der_atom(&value, &atom)) return false;
        if (atom.rawtag != 0x30) return false;
        value.l = atom.dl;
        value.d += atom.hl;
        if (!value.l) {
          /* CA flag is false and was properly omitted */
          o->caFlag = crit ? 0x80 : 0;
        } else {
          if (!read_der_atom(&value, &atom)) return false;
          if (atom.rawtag == 1) {
            /* CA flag is present */
            if (atom.dl != 1) return false;
            o->caFlag = (crit ? 0x80 : 0) | (*(value.d + atom.hl) ? 0x1 : 0);
          }
        }
      } else if (data_matches(&oid, &OID_SubjectAltName)) {
        o->subjectAltNames.d = value.d;
        o->subjectAltNames.l = value.l;
      } else if (data_matches(&oid, &OID_SubjectKeyIdentifier)) {
        if (!read_der_atom(&value, &atom)) return false;
        if (atom.rawtag != 4) return false;
        o->subjectKeyId.d = value.d + atom.hl;
        o->subjectKeyId.l = atom.dl;
      } else if (data_matches(&oid, &OID_AuthorityKeyIdentifier)) {
        if (!read_der_atom(&value, &atom)) return false;
        if (atom.rawtag != 0x30) return false;
        value.l = atom.dl;
        value.d += atom.hl;
        if (!read_der_atom(&value, &atom)) return false;
        if (atom.rawtag == 0x80) {
          o->issuerKeyId.d = value.d + atom.hl;
          o->issuerKeyId.l = atom.dl;
        }
      }
    } while (d.l);
  } while (0);
  if (o->vers >= 2) {
    o->isCA = (o->caFlag|0x80) == 0x81; /* HACK: some old CAs aren't critical! */
    o->isRoot = (o->isCA && o->subject.l && o->subject.l == o->issuer.l &&
                 memcmp(o->subject.d, o->issuer.d, o->subject.l) == 0) ? 1 : 0;
  } else {
    o->isCA = (o->subject.l && o->subject.l == o->issuer.l &&
               memcmp(o->subject.d, o->issuer.d, o->subject.l) == 0) ? 1 : 0;
    o->isRoot = o->isCA;
  }
  return true;
}

Boolean CheckCertOkay(SecCertificateRef _cert)
{
  CFDataRef d = cSecCertificateCopyData(_cert);
  data_t data;
  der_cert_t cert;
  Boolean ans;

  if (!d) return false;
  data.d = CFDataGetBytePtr(d);
  data.l = CFDataGetLength(d);
  ans = read_der_cert(&data, &cert);
  CFRelease(d);
  return ans;
}

/* flags & 0x01 to extract pub keys from certificates */
static Boolean CheckPubKeyOkayInt(CFDataRef d, data_t *pubkey, int flags)
{
  data_t data;

  if (!d || !pubkey) return false;
  data.d = CFDataGetBytePtr(d);
  data.l = CFDataGetLength(d);
  if (check_der_pubkey(&data)) {
    *pubkey = data;
    return true;
  }
  if (flags & 0x01) {
    der_cert_t cert;
    if (read_der_cert(&data, &cert)) {
      *pubkey = cert.subjectPubKey;
      return true;
    }
  }
  return false;
}

Boolean CheckPubKeyOkay(CFDataRef d)
{
  data_t data;
  return CheckPubKeyOkayInt(d, &data, 0);
}

static void append_hex_dump(CFMutableStringRef s, const void *_d, size_t l)
{
  const unsigned char *d = (unsigned char *)_d;
  CFStringAppendCString(s, "<", kCFStringEncodingASCII);
  while (l--) {
    char byte[3];
    sprintf(byte, "%02X", *d++);
    CFStringAppendCString(s, byte, kCFStringEncodingASCII);
  }
  CFStringAppendCString(s, ">", kCFStringEncodingASCII);
}

static CFStringRef CopyCertKeyId(SecCertificateRef _cert, bool issuer)
{
  CFDataRef d = cSecCertificateCopyData(_cert);
  CFMutableStringRef ans = CFStringCreateMutable(kCFAllocatorDefault, 0);
  bool good = false;

  for (;;) {
    data_t data;
    const data_t *key;
    der_cert_t cert;
    size_t i;

    if (!d || !ans) break;
    data.d = CFDataGetBytePtr(d);
    data.l = CFDataGetLength(d);
    if (!read_der_cert(&data, &cert)) break;
    key = issuer ? &cert.issuerKeyId : &cert.subjectKeyId;
    if (!key->d || !key->l) break;
    for (i = 0; i < key->l; ++i) {
      char hexbyte[4];
      sprintf(hexbyte, "%02X%s", (unsigned)key->d[i], i+1 == key->l ? "" : ":");
      CFStringAppendCString(ans, hexbyte, kCFStringEncodingASCII);
    }
    good = true;
    break;
  }
  if (d) CFRelease(d);
  if (!good && ans) {CFRelease(ans); ans=NULL;}
  return ans;
}

typedef struct oid_entry_s {
  size_t l;
  const char *oid;
  const char *name;
} oid_entry_t;

static const oid_entry_t oid_table[] = {
  {5, "\006\003\125\004\003", "CN"},
  {5, "\006\003\125\004\004", "SN"},
  {5, "\006\003\125\004\005", "serialNumber"},
  {5, "\006\003\125\004\006", "C"},
  {5, "\006\003\125\004\007", "L"},
  {5, "\006\003\125\004\010", "ST"},
  {5, "\006\003\125\004\011", "street"},
  {5, "\006\003\125\004\012", "O"},
  {5, "\006\003\125\004\013", "OU"},
  {5, "\006\003\125\004\014", "title"},
  {5, "\006\003\125\004\015", "description"},
  {5, "\006\003\125\004\017", "businessCategory"},
  {5, "\006\003\125\004\021", "postalCode"},
  {5, "\006\003\125\004\024", "telephoneNumber"},
  {5, "\006\003\125\004\027", "facsimileTelephoneNumber"},
  {5, "\006\003\125\004\052", "GN"},
  {5, "\006\003\125\004\053", "initials"},
  {5, "\006\003\125\004\054", "generationQualifier"},
  {5, "\006\003\125\004\056", "dnQualifier"},
  {5, "\006\003\125\004\101", "pseudonym"},
  {5, "\006\003\125\004\141", "organizationIdentifier"},
  {11, "\006\011\052\206\110\206\367\015\001\011\001", "emailAddress"},
  {12, "\006\012\011\222\046\211\223\362\054\144\001\001", "UID"},
  {12, "\006\012\011\222\046\211\223\362\054\144\001\031", "DC"},
  {13, "\006\013\053\006\001\004\001\202\067\074\002\001\001", "jurisdictionOfIncorporationLocality"},
  {13, "\006\013\053\006\001\004\001\202\067\074\002\001\002", "jurisdictionOfIncorporationStateOrProvince"},
  {13, "\006\013\053\006\001\004\001\202\067\074\002\001\003", "jurisdictionOfIncorporationCountry"}
};
#define oid_table_size (sizeof(oid_table)/sizeof(oid_table[0]))

static int comp_entry(const void *_e1, const void *_e2)
{
  const oid_entry_t *o1 = (oid_entry_t *)_e1;
  const oid_entry_t *o2 = (oid_entry_t *)_e2;
  size_t min = o1->l;
  int ans;
  if (o2->l < min) min = o2->l;
  ans = memcmp(o1->oid, o2->oid, min);
  if (ans) return ans;
  if (o1->l < o2->l) return -1;
  if (o1->l > o2->l) return 1;
  return 0;
}

static void append_oid_name(CFMutableStringRef s, const char *prefix,
                            const void *_oid, size_t l, const char *suffix)
{
  oid_entry_t find, *ans;
  find.oid = (char *)_oid;
  find.l = l;
  find.name = NULL;
  ans = (oid_entry_t *)
    bsearch(&find, oid_table, oid_table_size, sizeof(find), comp_entry);
  if (prefix && *prefix)
    CFStringAppendCString(s, prefix, kCFStringEncodingASCII);
  if (ans)
    CFStringAppendCString(s, ans->name, kCFStringEncodingASCII);
  else {
    CFMutableStringRef temp = CFStringCreateMutable(kCFAllocatorDefault, 0);
    const uint8_t *oid = (uint8_t *)_oid;
    bool bad = false;
    size_t orig_l = l;
    const uint8_t *orig_oid = oid;
    if (!temp || l < 3 || *oid != 6)
      bad = true;
    if (!bad) {
      data_t data;
      der_atom_t atom;
      data.d = oid;
      data.l = l;
      if (!read_der_atom(&data, &atom))
        bad = true;
      if (!bad && (atom.rawtag != 6 || atom.dl < 1))
        bad = true;
      if (!bad) {
        oid = data.d + atom.hl;
        l = atom.dl;
        if (l + atom.hl != orig_l)
          bad = true;
      }
    }
    if (!bad) {
      size_t idx = 0;
      do {
        unsigned idval = 0;
        uint8_t byte;
        do {
          if (!l) {bad=true; break;}
          idval <<= 7;
          byte = *oid++;
          --l;
          idval |= byte & 0x7f;
        } while (!bad && (byte & 0x80));
        if (bad) break;
        if (!idx) {
          char twoids[32];
          unsigned x, y;
          if (idval < 40) {
            x = 0; y = idval;
          } else if (idval < 80) {
            x = 1; y = idval - 40;
          } else {
            x = 2; y = idval - 80;
          }
          snprintf(twoids, sizeof(twoids), "%u.%u", x, y);
          CFStringAppendCString(temp, twoids, kCFStringEncodingASCII);
          idx += 2;
        } else {
          char oneid[16];
          snprintf(oneid, sizeof(oneid), ".%u", idval);
          CFStringAppendCString(temp, oneid, kCFStringEncodingASCII);
          ++idx;
        }
      } while (l && !bad);
    }
    if (bad || l || !temp || !CFStringGetLength(temp))
      append_hex_dump(s, orig_oid, orig_l);
    else
      CFStringAppend(s, temp);
    if (temp)
      CFRelease(temp);
  }
  if (suffix && *suffix)
    CFStringAppendCString(s, suffix, kCFStringEncodingASCII);
}

#define DER_TAG_UTF8STRING 12
#define DER_TAG_NUMERICSTRING 18
#define DER_TAG_PRINTABLESTRING 19
#define DER_TAG_TELETEXSTRING 20
#define DER_TAG_VIDEOTEXSTRING 21
#define DER_TAG_IA5STRING 22
#define DER_TAG_GRAPHICSTRING 25
#define DER_TAG_VISIBLESTRING 26
#define DER_TAG_GENERALSTRING 27
#define DER_TAG_UNIVERSALSTRING 28
#define DER_TAG_BMPSTRING 30

/* flags:
 *   0x01 => strings only
 *   0x02 => 8-bit strings only
 *   0x04 => CN Ids strings only
 *   0x08 => wildcard CN okay
 *   0x10 => create output string
 */
static bool append_attr_value(CFMutableStringRef *s, const void *_d,
                              const der_atom_t *a, unsigned flags)
{
  const uint8_t *d = (uint8_t *)_d;
  CFStringBuiltInEncodings encoding = kCFStringEncodingASCII;
  CFStringRef temp;
  if (s && !(flags & 0x10) && !*s) return false;
  if (!s || !d || !a || !a->dl) return false;
  switch (a->rawtag) {
    case DER_TAG_UTF8STRING:
    case DER_TAG_GRAPHICSTRING:
    case DER_TAG_GENERALSTRING:
    case DER_TAG_UNIVERSALSTRING:
      encoding = kCFStringEncodingUTF8; break;
    case DER_TAG_NUMERICSTRING:
    case DER_TAG_PRINTABLESTRING:
    case DER_TAG_IA5STRING:
      encoding = kCFStringEncodingASCII; break;
    case DER_TAG_TELETEXSTRING:
    case DER_TAG_VIDEOTEXSTRING:
    case DER_TAG_VISIBLESTRING:
      encoding = kCFStringEncodingISOLatin1; break;
    case DER_TAG_BMPSTRING:
      if (flags & 0x06) return false;
      encoding = kCFStringEncodingUnicode; break;
    default:
      if (flags & 0x05) return false;
      append_hex_dump(*s, d, a->hl + a->dl);
      return true;
  }
  if (flags & 0x04 && !is_dns_name(d+a->hl, a->dl, !!(flags & 0x08)))
    return false;
  temp = CFStringCreateWithBytes(kCFAllocatorDefault, d+a->hl, a->dl,
                                 encoding, true);
  if (temp) {
    if (flags & 0x10)
      *s = CFStringCreateMutable(kCFAllocatorDefault, 0);
    if (*s)
      CFStringAppend(*s, temp);
    CFRelease(temp);
  } else {
    if (flags & 0x05) return false;
    append_hex_dump(*s, d, a->hl + a->dl);
  }
  return *s != NULL;
}

CF_INLINE int is_dig(char c)
{
  return '0' <= c && c <= '9';
}

static void append_year_string(CFMutableStringRef cfstr, const char *vstr)
{
  size_t vl = strlen(vstr);
  if ((vl == 13 || vl == 15) && vstr[vl - 1] == 'Z') {
    size_t off = 4;
    unsigned short uc[4];
    if (vl == 13 && is_dig(vstr[0]) && is_dig(vstr[1])) {
      int yr2 = (vstr[0] - '0') * 10 + (vstr[1] - '0');
      if (yr2 >= 50) {
        uc[0] = '1';
        uc[1] = '9';
      } else {
        uc[0] = '2';
        uc[1] = '0';
      }
      uc[2] = (unsigned char)vstr[0];
      uc[3] = (unsigned char)vstr[1];
      off = 2;
    } else {
      uc[0] = vstr[0];
      uc[1] = vstr[1];
      uc[2] = vstr[2];
      uc[3] = vstr[3];
    }
    CFStringAppendCharacters(cfstr, uc, 4);
    uc[0] = '-';
    uc[1] = vstr[off];
    uc[2] = vstr[off+1];
    uc[3] = '-';
    CFStringAppendCharacters(cfstr, uc, 4);
    uc[0] = vstr[off+2];
    uc[1] = vstr[off+3];
    uc[2] = 'T';
    CFStringAppendCharacters(cfstr, uc, 3);
    uc[0] = vstr[off+4];
    uc[1] = vstr[off+5];
    uc[2] = ':';
    CFStringAppendCharacters(cfstr, uc, 3);
    uc[0] = vstr[off+6];
    uc[1] = vstr[off+7];
    CFStringAppendCharacters(cfstr, uc, 3);
    uc[0] = vstr[off+8];
    uc[1] = vstr[off+9];
    uc[2] = 'Z';
    CFStringAppendCharacters(cfstr, uc, 3);
  } else {
    CFStringAppendCString(cfstr, vstr, kCFStringEncodingASCII);
  }
}

void CopyCertValidity(SecCertificateRef _cert, CFStringRef *_nb, CFStringRef *_na)
{
  CFDataRef d = cSecCertificateCopyData(_cert);
  CFMutableStringRef nb, na;
  data_t data;
  der_cert_t cert;

  if (!d || !_nb || !_na) return;
  *_nb = NULL;
  *_na = NULL;
  data.d = CFDataGetBytePtr(d);
  data.l = CFDataGetLength(d);
  if (!read_der_cert(&data, &cert)) {
    CFRelease(d);
    return;
  }
  CFRelease(d);
  nb = CFStringCreateMutable(kCFAllocatorDefault, 0);
  if (!nb)
    return;
  na = CFStringCreateMutable(kCFAllocatorDefault, 0);
  if (!na) {
    CFRelease(nb);
    return;
  }
  append_year_string(nb, cert.notBefore);
  append_year_string(na, cert.notAfter);
  *_nb = nb;
  *_na = na;
}

static CFStringRef CopyCertName(SecCertificateRef _cert, bool issuer)
{
  CFDataRef d = cSecCertificateCopyData(_cert);
  CFMutableStringRef ans = CFStringCreateMutable(kCFAllocatorDefault, 0);
  bool good = false;

  for (;;) {
    data_t data;
    const data_t *name;
    der_cert_t cert;
    der_atom_t atom;
    bool badset = false;

    if (!d || !ans) break;
    data.d = CFDataGetBytePtr(d);
    data.l = CFDataGetLength(d);
    if (!read_der_cert(&data, &cert)) break;
    name = issuer ? &cert.issuer : &cert.subject;
    data.d = name->d;
    data.l = name->l;
    if (data.d && data.l) {
      if (!read_der_atom(&data, &atom)) break;
      if (atom.rawtag != 0x30) break;
      data.l -= atom.hl;
      data.d += atom.hl;
      while (data.l) {
        data_t set;
        unsigned setidx = 0;
        badset = true;
        if (!read_der_atom(&data, &atom)) break;
        if (atom.rawtag != 0x31) break;
        set.d = data.d + atom.hl;
        set.l = atom.dl;
        data.l -= atom.hl + atom.dl;
        data.d += atom.hl + atom.dl;
        for (;;) {
          data_t oid;
          if (!read_der_atom(&set, &atom)) break;
          if (atom.rawtag != 0x30) break;
          set.l -= atom.hl;
          set.d += atom.hl;
          if (!read_der_atom(&set, &atom)) break;
          if (atom.rawtag != 6) break;
          oid.d = set.d;
          oid.l = atom.hl + atom.dl;
          set.l -= atom.hl + atom.dl;
          set.d += atom.hl + atom.dl;
          if (!read_der_atom(&set, &atom)) break;
          append_oid_name(ans, setidx++?"/+":"/", oid.d, oid.l, "=");
          append_attr_value(&ans, set.d, &atom, 0);
          set.l -= atom.hl + atom.dl;
          set.d += atom.hl + atom.dl;
          if (!set.l) {
            badset=false;
            break;
          }
        }
        if (badset) break;
      }
      if (badset || data.l) break;
      good = true;
    }
    break;
  }
  if (d) CFRelease(d);
  if (!good && ans) {CFRelease(ans); ans=NULL;}
  return MakeVisibleString(ans);
}

CFStringRef CopyCertSubject(SecCertificateRef _cert)
{
  return CopyCertName(_cert, false);
}

CFStringRef CopyCertSubjectKeyId(SecCertificateRef _cert)
{
  return CopyCertKeyId(_cert, false);
}

CFStringRef CopyCertIssuer(SecCertificateRef _cert)
{
  return CopyCertName(_cert, true);
}

CFStringRef CopyCertIssuerKeyId(SecCertificateRef _cert)
{
  return CopyCertKeyId(_cert, true);
}

/* return CFArrayRef if arr else CFStringRef
 * flags:
 *   0x01 includes DNS alts
 *   0x02 includes IPv4 alts
 *   0x04 includes IPv6 alts
 *   0x08 include IP other alts
 */
static CFTypeRef CopyCertSubjectAltNamesInt(const der_cert_t *cert, bool arr, unsigned flags)
{
  data_t data;
  CFTypeRef ans = arr ?
    (CFTypeRef)CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks) :
    (CFTypeRef)CFStringCreateMutable(kCFAllocatorDefault, 0);
  bool good = false;

  do {
    der_atom_t atom;

    if (!cert || !ans) break;
    if (!cert->subjectAltNames.d || !cert->subjectAltNames.l) break;
    data.d = cert->subjectAltNames.d;
    data.l = cert->subjectAltNames.l;
    if (!read_der_atom(&data, &atom)) break;
    if (atom.rawtag != 0x30) break;
    data.l -= atom.hl;
    data.d += atom.hl;
    do {
      if (!read_der_atom(&data, &atom)) break;
      if (atom.rawtag == 0x82 && (flags & 0x01)) {
        CFStringRef temp;
        if (!arr && CFStringGetLength((CFStringRef)ans))
          CFStringAppendCString((CFMutableStringRef)ans, ",", kCFStringEncodingASCII);
        temp = CFStringCreateWithBytes(kCFAllocatorDefault, data.d+atom.hl,
                                       atom.dl, kCFStringEncodingASCII, true);
        if (!temp) break;
        if (arr)
          CFArrayAppendValue((CFMutableArrayRef)ans, temp);
        else
          CFStringAppend((CFMutableStringRef)ans, temp);
        CFRelease(temp);
      } else if (atom.rawtag == 0x87 && (flags & 0x0e)) {
        if ((atom.dl == 4 && (flags & 0x02)) ||
            (atom.dl == 16 && (flags & 0x04)) ||
            (atom.dl != 4 && atom.dl != 16 && (flags & 0x08))) {
          if (arr) {
            CFDataRef dtemp = CFDataCreate(kCFAllocatorDefault, data.d+atom.hl, atom.dl);
            if (!dtemp) break;
            CFArrayAppendValue((CFMutableArrayRef)ans, dtemp);
            CFRelease(dtemp);
          } else {
            if (CFStringGetLength((CFStringRef)ans))
              CFStringAppendCString((CFMutableStringRef)ans, ",", kCFStringEncodingASCII);
            if (atom.dl == 4) {
              char ipv4str[16];
              const uint8_t *ip = data.d+atom.hl;
              sprintf(ipv4str, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
              CFStringAppendCString((CFMutableStringRef)ans, ipv4str, kCFStringEncodingASCII);
            } else if (atom.dl == 16) {
              char ntopbuff[INET6_ADDRSTRLEN];
              if (!inet_ntop(AF_INET6, data.d+atom.hl, ntopbuff, sizeof(ntopbuff)))
                break;
              CFStringAppendCString((CFMutableStringRef)ans, ntopbuff, kCFStringEncodingASCII);
            } else {
              append_hex_dump((CFMutableStringRef)ans, data.d+atom.hl, atom.dl);
            }
          }
        }
      }
      data.l -= atom.hl + atom.dl;
      data.d += atom.hl + atom.dl;
    } while (data.l);
    if (!data.l && ( (arr  && CFArrayGetCount((CFArrayRef)ans)   ) ||
                     (!arr && CFStringGetLength((CFStringRef)ans))    ))
      good = true;
  } while (0);
  if (!good && ans) {CFRelease(ans); ans=NULL;}
  return ans;
}

static CFArrayRef CopyCertSubjectCNIds(const der_cert_t *cert)
{
  CFMutableArrayRef ans =
    CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  bool good = false;

  do {
    data_t data;
    der_atom_t atom;

    if (!ans || !cert || !cert->subject.d || !cert->subject.l) break;
    data.d = cert->subject.d;
    data.l = cert->subject.l;
    if (!read_der_atom(&data, &atom)) break;
    if (atom.rawtag != 0x30) break;
    data.l -= atom.hl;
    data.d += atom.hl;
    while (data.l) {
      data_t set;
      if (!read_der_atom(&data, &atom)) break;
      if (atom.rawtag != 0x31) break;
      set.d = data.d + atom.hl;
      set.l = atom.dl;
      data.l -= atom.hl + atom.dl;
      data.d += atom.hl + atom.dl;
      if (!read_der_atom(&set, &atom)) break;
      if (atom.rawtag != 0x30) break;
      if (atom.hl + atom.dl == set.l) { /* single-value CN only */
        CFMutableStringRef cnid;
        data_t oid;
        set.l -= atom.hl;
        set.d += atom.hl;
        if (!read_der_atom(&set, &atom)) break;
        if (atom.rawtag != 6) break;
        oid.d = set.d;
        oid.l = atom.hl + atom.dl;
        if (data_matches(&oid, &OID_CommonName)) {
          set.l -= atom.hl + atom.dl;
          set.d += atom.hl + atom.dl;
          if (!read_der_atom(&set, &atom)) break;
          if (append_attr_value(&cnid, set.d, &atom, 0x1f) && cnid) {
            CFArrayAppendValue(ans, cnid);
            CFRelease(cnid);
          }
        }
      }
    }
    if (!data.l)
      good = true;
  } while (0);
  if (ans && (!good || !CFArrayGetCount(ans))) {
    CFRelease(ans);
    ans=NULL;
  }
  return ans;
}

CFStringRef CopyCertSubjectAltNamesString(SecCertificateRef _cert)
{
  CFDataRef d = cSecCertificateCopyData(_cert);
  data_t data;
  der_cert_t cert;
  CFStringRef ans = NULL;

  if (!d) return NULL;
  data.d = CFDataGetBytePtr(d);
  data.l = CFDataGetLength(d);
  if (read_der_cert(&data, &cert))
      ans = (CFStringRef)CopyCertSubjectAltNamesInt(&cert, false, 0x0f);
  CFRelease(d);
  return MakeVisibleString(ans);
}

/* mode:
 *   0 = DNS/CN ids
 *   4 = IPv4 ids
 *   16 = IPv6 ids
 */
static CFArrayRef CopyCertSubjectIds(der_cert_t *c, unsigned mode)
{
  CFArrayRef ans = NULL;
  if (!c || (mode != 0 && mode != 4 && mode != 16)) return NULL;
  if (mode == 4)
    return ans = (CFArrayRef)CopyCertSubjectAltNamesInt(c, true, 0x02);
  if (mode == 16)
    return ans = (CFArrayRef)CopyCertSubjectAltNamesInt(c, true, 0x04);
  else {
    ans = (CFArrayRef)CopyCertSubjectAltNamesInt(c, true, 0x01);
    if (!ans || !CFArrayGetCount(ans)) {
      if (ans) CFRelease(ans);
      ans = CopyCertSubjectCNIds(c);
    }
  }
  if (ans && !CFArrayGetCount(ans)) {
    CFRelease(ans);
    ans = NULL;
  }
  return ans;
}

OSStatus VerifyTrustChain(SecTrustRef trust, CFArrayRef customRootsOrNull,
              unsigned certFlags, unsigned flags, const char *peername,
              CFArrayRef pinnedKeySet)
{
  SecTrustResultType result;
  CFArrayRef chain = NULL;
  CSSM_TP_APPLE_EVIDENCE_INFO *evidence;
  bool pkonly = (certFlags & 0x02) ? true : false;
  bool explicitCertsOnly = (certFlags & 0x01) ? true : false;
  bool nameonly = (certFlags & 0x04) ? true : false;
  OSStatus err;
  size_t i, cnt;
  if ((pinnedKeySet && !CFArrayGetCount(pinnedKeySet)) || (pkonly && !pinnedKeySet))
    return paramErr;
  if (nameonly && !pkonly && (!peername || !*peername))
    return paramErr;
  err = cSecTrustGetResult(trust, &result, &chain, &evidence);
  if (err == errSecTrustNotAvailable) {
    /* We need to evaluate first */
    CFArrayRef anchors = customRootsOrNull;
    if (chain) CFRelease(chain);
    if (anchors)
      CFRetain(anchors);
    else {
      err = SecTrustCopyAnchorCertificates(&anchors);
      if (err) return err;
    }
    err = SecTrustSetAnchorCertificates(trust, anchors);
    CFRelease(anchors);
    if (err) return err;
    err = cSecTrustSetAnchorCertificatesOnly(trust, customRootsOrNull ? true : false);
    if (err && err != unimpErr) return err;
    err = SecTrustEvaluate(trust, &result);
    if (err && !pkonly && !nameonly) return err;
    chain = NULL;
    err = cSecTrustGetResult(trust, &result, &chain, &evidence);
  }
  if (err) {
    if (chain) CFRelease(chain);
    return err;
  }
  if (!chain || !evidence || !CFArrayGetCount(chain)) {
    if (chain) CFRelease(chain);
    return errSSLXCertChainInvalid;
  }
  if (pkonly) goto pinned_key_check;
  cnt = (size_t)CFArrayGetCount(chain);
  if ((peername && *peername) ||
      (!(flags & CSSM_TP_ACTION_LEAF_IS_CA) &&
       !(evidence[0].StatusBits & CSSM_CERT_STATUS_IS_ROOT))) {
    CFDataRef certder = cSecCertificateCopyData(
                          (SecCertificateRef)CFArrayGetValueAtIndex(chain, 0));
    data_t der;
    der_cert_t cert;
    if (!certder)
      return errSSLBadCert;
    der.d = CFDataGetBytePtr(certder);
    der.l = CFDataGetLength(certder);
    if (!read_der_cert(&der, &cert))
      err = errSSLBadCert;

    /* First confirm we have a host name match.  SecureTransport should do
     * this for us (but will not give us a decent result code) except that
     * it has problems with IPv6 address matching */
    if (!err && peername && *peername) {
      size_t peerlen = strlen(peername);
      union {
        uint8_t ipv6[16];
        uint8_t ipv4[4];
      } ipa;
      int mode = -1;
      if (parse_ipv4_name(peername, peerlen, ipa.ipv4)) mode = 4;
      else if (is_dns_name(peername, peerlen, false)) mode = 0;
      else if (parse_ipv6_name(peername, peerlen, ipa.ipv6)) mode = 16;
      if (mode == -1)
        /* if we can't parse peername it can't possibly match! */
        err = errSSLHostNameMismatch;
      if (!err) {
        CFArrayRef ids = CopyCertSubjectIds(&cert, mode);
        if (ids && !CFArrayGetCount(ids)) {
          CFRelease(ids);
          ids = NULL;
        }
        if (!ids)
          /* if we don't have anything to match against it can't possibly match! */
          err = errSSLHostNameMismatch;
        else {
          size_t j, idcnt = CFArrayGetCount(ids);
          bool matched = false;
          for (j = 0; j < idcnt; ++j) {
            CFTypeRef oneid = (CFTypeRef)CFArrayGetValueAtIndex(ids, j);
            if (mode) {
              const uint8_t *p;
              size_t l;
              if (CFDataGetTypeID() != CFGetTypeID(oneid)) continue;
              p = (uint8_t *)CFDataGetBytePtr((CFDataRef)oneid);
              l = (size_t)CFDataGetLength((CFDataRef)oneid);
              if (l != (size_t)mode) continue;
              if (memcmp(ipa.ipv6, p, l) == 0) {
                matched = true;
                break;
              }
            } else {
              CFDataRef dnsname;
              if (CFStringGetTypeID() != CFGetTypeID(oneid)) continue;
              dnsname = CFStringCreateExternalRepresentation(
                kCFAllocatorDefault, (CFStringRef)oneid,
                kCFStringEncodingASCII, 0);
              if (!dnsname) continue;
              if (peername_matches_id(peername, dnsname))
                matched = true;
              CFRelease(dnsname);
              if (matched)
                break;
            }
          }
          CFRelease(ids);
          if (!matched)
            err = errSSLHostNameMismatch;
        }
      }
    }

    /* Confirm that the first certificate is NOT a CA (otherwise it's not a
     * valid chain), but again SecureTransport should have already checked that
     * for us.  CSSM_TP_ACTION_LEAF_IS_CA overrides.  Also we never check the
     * root certificate even if it's also the leaf. */
    if (!nameonly && !err && !(flags & CSSM_TP_ACTION_LEAF_IS_CA) &&
        !(evidence[0].StatusBits & CSSM_CERT_STATUS_IS_ROOT) && cert.isCA)
      err = errSSLXCertChainInvalid;

    CFRelease(certder);
    if (err) return err;
  }
  if (nameonly) goto pinned_key_check;
  if (explicitCertsOnly) {
    /* Check all but root */
    for (i = 0; i < cnt; ++i) {
      if (!(evidence[i].StatusBits & CSSM_CERT_STATUS_IS_IN_INPUT_CERTS) &&
          !(evidence[i].StatusBits & CSSM_CERT_STATUS_IS_ROOT)) {
        /* If the magical cert had not appeared, the chain would have stopped
         * here and the error would be no root, so return that error */
        CFRelease(chain);
        return errSSLNoRootCert;
      }
    }
  }
  if (!(flags & CSSM_TP_ACTION_ALLOW_EXPIRED) ||
      !(flags & CSSM_TP_ACTION_ALLOW_EXPIRED_ROOT)) {
    /* check for expired or not yet valid certs */
    for (i = 0; i < cnt; ++i) {
      if ((flags & CSSM_TP_ACTION_ALLOW_EXPIRED) &&
          !(evidence[i].StatusBits & CSSM_CERT_STATUS_IS_ROOT))
        continue;
      if ((flags & CSSM_TP_ACTION_ALLOW_EXPIRED_ROOT) &&
          (evidence[i].StatusBits & CSSM_CERT_STATUS_IS_ROOT))
        continue;
      if (evidence[i].StatusBits & CSSM_CERT_STATUS_EXPIRED) {
        CFRelease(chain);
        return errSSLCertExpired;
      }
      if (evidence[i].StatusBits & CSSM_CERT_STATUS_NOT_VALID_YET) {
        CFRelease(chain);
        return errSSLCertNotYetValid;
      }
    }
  }
  /* check for no root */
  if (!(evidence[cnt-1].StatusBits & CSSM_CERT_STATUS_IS_ROOT)) {
    CFRelease(chain);
    return errSSLNoRootCert;
  }
  /* check for unknown root */
  if (!(evidence[cnt-1].StatusBits & CSSM_CERT_STATUS_IS_IN_ANCHORS)) {
    CFRelease(chain);
    return errSSLUnknownRootCert;
  }
  if (customRootsOrNull) {
    /* make sure we're not using a gratuitous root, Mac OS X likes to just
     * go ahead and use its anchors sometimes despite settings to the contrary */
    if (!SecCertInArray((SecCertificateRef)CFArrayGetValueAtIndex(chain, cnt-1),
                        customRootsOrNull)) {
      CFRelease(chain);
      return errSSLNoRootCert;
    }
  }
  /* everything looks good, so check the trust result code now */
  switch (result) {
    case kSecTrustResultProceed:
    case kSecTrustResultUnspecified:
      /* good result */
      break;
    case kSecTrustResultDeny:
      /* DENIED! */
      CFRelease(chain);
      return errSecTrustSettingDeny;
    default:
      /* everything else (confirm, invalid, recoverable, fatal, other) */
      CFRelease(chain);
      return errSecNotTrusted;
  }
  pinned_key_check:
  if (pinnedKeySet) {
    CFDataRef certder = cSecCertificateCopyData(
                          (SecCertificateRef)CFArrayGetValueAtIndex(chain, 0));
    data_t der;
    der_cert_t cert;
    CFDataRef peerPubKey;
    bool pinok;
    if (!certder)
      return errSSLBadCert;
    der.d = CFDataGetBytePtr(certder);
    der.l = CFDataGetLength(certder);
    if (!read_der_cert(&der, &cert)) {
      CFRelease(certder);
      return errSSLBadCert;
    }
    peerPubKey = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
      cert.subjectPubKey.d, cert.subjectPubKey.l, kCFAllocatorNull);
    if (!peerPubKey) {
      CFRelease(certder);
      return memFullErr;
    }
    pinok = BlobInArray(peerPubKey, pinnedKeySet);
    CFRelease(peerPubKey);
    CFRelease(certder);
    if (!pinok)
      return errSecPinnedKeyMismatch;
  }
  CFRelease(chain);
  return noErr;
}

#elif TARGET_OS_EMBEDDED || TARGET_OS_IPHONE

#error iOS is not currently supported

#endif /* TARGET_OS_EMBEDDED || TARGET_OS_IPHONE */
