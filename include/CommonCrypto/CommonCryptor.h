#ifndef _CC_COMMON_CRYPTOR_
#define _CC_COMMON_CRYPTOR_

#include <stddef.h>

typedef int CCCryptorStatus;
#define kCCSuccess 0
#define kCCParamError -4300
#define kCCUnimplemented -4305
#define kCCEncrypt 0
#define kCCDecrypt 1
#define kCCAlgorithmDES 1
#define kCCOptionECBMode 2
#define kCCKeySizeDES 8

CCCryptorStatus cCCCrypt(int, int, int, const void *, size_t, const void *,
                         const void *, size_t, void *, size_t, size_t *);

#define CCCrypt(a,b,c,d,e,f,g,h,i,j,k) cCCCrypt(a,b,c,d,e,f,g,h,i,j,k)

#endif /* _CC_COMMON_CRYPTOR_ */
