#ifndef _CC_COMMON_EVP_H_
#define _CC_COMMON_EVP_H_

int cEVP_EncodeBlock(void *,const void *,int);
int cEVP_DecodeBlock(void *,const void *,int);

#define EVP_EncodeBlock(t,f,l) cEVP_EncodeBlock(t,f,l)
#define EVP_DecodeBlock(t,f,l) cEVP_DecodeBlock(t,f,l)

#endif /* _CC_COMMON_EVP_H_ */
