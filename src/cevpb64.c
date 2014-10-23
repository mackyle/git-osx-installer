/*

cevpb64.c -- compatibility implemenation of EVP base 64 functions
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

#include <stddef.h>

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

static void decode24(const unsigned char *input, unsigned char *output)
{
  output[0] = ((b64tab[input[0]]&0x3F)<<2)|((b64tab[input[1]]&0x3F)>>4);
  output[1] = (((b64tab[input[1]]&0x3F)&0x0F)<<4)|((b64tab[input[2]]&0x3F)>>2);
  output[2] = (((b64tab[input[2]]&0x3F)&0x03)<<6)|(b64tab[input[3]]&0x3F);
}

static int DecodeBase64Block(const void *_in, size_t inl, void *_out, size_t *outl)
{
  const unsigned char *in = (unsigned char *)_in;
  unsigned char *out = (unsigned char *)_out;
  unsigned char inb[4];
  unsigned char outb[3];
  size_t count;
  int i;

  if (inl && !in)
    return -1;
  if (!inl) {
    *outl = 0;
    return 0;
  }
  count = 0;
  for (i=0; inl; ++in, --inl) {
    unsigned char c = *in;
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f')
      continue;
    if (b64tab[c] < 0)
      return -1;
    inb[i++] = c;
    if (i == 4) {
      decode24(inb, outb);
      i = 0;
      if (inb[3] == '=') {
        *out++ = outb[0];
        ++count;
        if (inb[2] != '=') {
          *out++ = outb[1];
          ++count;
        }
        break;
      }
      *out++ = outb[0];
      *out++ = outb[1];
      *out++ = outb[2];
      count += 3;
    }
  }
  if (i != 0)
    return -1;
  *outl = count;
  return 0;
}

static const char tab64[64] = {
'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
};

static void encode24(const unsigned char *input, unsigned char *output)

{
    output[0] = tab64[input[0]>>2];
    output[1] = tab64[((input[0]&0x3)<<4)+(input[1]>>4)];
    output[2] = tab64[((input[1]&0xF)<<2)+(input[2]>>6)];
    output[3] = tab64[input[2]&0x3F];
}

static int EncodeBase64Block(const void *_in, size_t inl, void *_out, size_t *outl)
{
  const unsigned char *in = (unsigned char *)_in;
  unsigned char *out = (unsigned char *)_out;
  size_t count;
  int i;

  if (inl && !in)
    return -1;
  if (!inl) {
    *outl = 0;
    return 0;
  }
  count = 0;
  for (i=0; inl >= 3; in+=3, inl-=3) {
    encode24(in, out);
    out += 4;
    count += 4;
  }
  if (inl) {
    unsigned char inb[3];
    inb[0] = *in;
    inb[1] = inl == 2 ? in[1] : '\0';
    inb[2] = '\0';
    encode24(inb, out);
    count += 4;
  }
  *outl = count;
  return 0;
}

int cEVP_DecodeBlock(void *to, const void *from, int fromlen)
{
  int err;
  size_t ans;

  if (fromlen < 0)
    return -1;
  err = DecodeBase64Block(from, (size_t)fromlen, to, &ans);
  if (err)
    return -1;
  return (int)ans;
}

int cEVP_EncodeBlock(void *to, const void *from, int fromlen)
{
  int err;
  size_t ans;

  if (fromlen < 0)
    return -1;
  err = EncodeBase64Block(from, (size_t)fromlen, to, &ans);
  if (err)
    return -1;
  return (int)ans;
}
