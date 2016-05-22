/*

ccchmac.c -- compatibility implemenation of CCHmac functions for MD5
Copyright (c) 2014 Kyle J. McKay.  All rights reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#include <CommonCrypto/CommonDigest.h>
#include <string.h>

#define kCCHmacAlgMD5 1

typedef struct {
  CC_MD5_CTX md5ctx;
  unsigned char keydata[CC_MD5_BLOCK_BYTES];
} CCHmacContext;

/*
 * RFC 2104 defines the HMAC computation
 * We only support H = MD5 (B=CC_MD5_BLOCK_BYTES)
 */

extern void die(const char *err, ...);

void cCCHmacInit(CCHmacContext *ctx, int alg, const void *k, size_t kl)
{
  size_t i;

  if (alg != kCCHmacAlgMD5)
    die("cCCHmacInit requires kCCHmacAlgMD5");

  /* 1. Get CC_MD5_BLOCK_BYTES byte key */
  if (kl > CC_MD5_BLOCK_BYTES)
    kl = CC_MD5_BLOCK_BYTES;
  memcpy(ctx->keydata, k, kl);
  if (kl < CC_MD5_BLOCK_BYTES)
    memset(&ctx->keydata[kl], 0, CC_MD5_BLOCK_BYTES - kl);

  /* 2. XOR step 1 key with 0x36 */
  for (i=0; i<CC_MD5_BLOCK_BYTES; ++i)
    ctx->keydata[i] ^= 0x36;

  /* 3. Append text to the result of step 2 */
  /* 4. Compute MD5 of result of step 3 */
  CC_MD5_Init(&ctx->md5ctx);
  CC_MD5_Update(&ctx->md5ctx, ctx->keydata, CC_MD5_BLOCK_BYTES);
}

void cCCHmacUpdate(CCHmacContext *ctx, const void *d, size_t dl)
{
  /* 3. Append text to the result of step 2 */
  /* 4. Compute MD5 of result of step 3 */
  CC_MD5_Update(&ctx->md5ctx, d, (CC_LONG)dl);
}

void cCCHmacFinal(CCHmacContext *ctx, void *m)
{
  size_t i;
  unsigned char md5[CC_MD5_DIGEST_LENGTH];

  /* 4. Compute MD5 of result of step 3 */
  CC_MD5_Final(md5, &ctx->md5ctx);

  /* 5. XOR step 1 key with 0x5c */
  for (i=0; i<CC_MD5_BLOCK_BYTES; ++i)
    ctx->keydata[i] ^= (0x36 ^ 0x5c);

  /* 6. Append MD5 result from step 4 to result of step 5 */
  /* 7. Compute MD5 of result of step 6 and output the result */
  CC_MD5_Init(&ctx->md5ctx);
  CC_MD5_Update(&ctx->md5ctx, ctx->keydata, CC_MD5_BLOCK_BYTES);
  CC_MD5_Update(&ctx->md5ctx, md5, CC_MD5_DIGEST_LENGTH);
  CC_MD5_Final(m, &ctx->md5ctx);
}

void cCCHmac(int alg, const void *k, size_t kl, const void *d, size_t dl, void *m)
{
  CCHmacContext ctx;

  cCCHmacInit(&ctx, alg, k, kl);
  cCCHmacUpdate(&ctx, d, dl);
  cCCHmacFinal(&ctx, m);
}
