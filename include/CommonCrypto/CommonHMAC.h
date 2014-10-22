#ifndef _CC_COMMON_HMAC_H_
#define _CC_COMMON_HMAC_H_

#include <stddef.h>
#include <CommonCrypto/CommonDigest.h>

#define kCCHmacAlgMD5 1

typedef struct {
	CC_MD5_CTX md5ctx;
	unsigned char keydata[64];
} CCHmacContext;

void cCCHmacInit(CCHmacContext *,int,const void *,size_t);
void cCCHmacUpdate(CCHmacContext *,const void *,size_t);
void cCCHmacFinal(CCHmacContext *, void *);

#define CCHmacInit(c,a,k,l) cCCHmacInit(c,a,k,l)
#define CCHmacUpdate(c,d,l) cCCHmacUpdate(c,d,l)
#define CCHmacFinal(c,m) cCCHmacFinal(c,m)

int cEVP_EncodeBlock(void *,const void *,int);
int cEVP_DecodeBlock(void *,const void *,int);

#define EVP_EncodeBlock(t,f,l) cEVP_EncodeBlock(t,f,l)
#define EVP_DecodeBlock(t,f,l) cEVP_DecodeBlock(t,f,l)

#endif /* _CC_COMMON_HMAC_H_ */
