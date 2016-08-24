#define _MD5_

#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"

// Domain to use for mangling
__constant u8 domain[] = "linkedin.com";
__constant u32x domain_len = 12;

// Characters used for base64 encoding
__constant char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Perform an MD5 transform step
// Should be called through hmac_md5_pad_mangle and hmac_md5_run_mangle
void md5_transform_mangle (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], u32x digest[4])
{
  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];

  u32x w0_t = w0[0];
  u32x w1_t = w0[1];
  u32x w2_t = w0[2];
  u32x w3_t = w0[3];
  u32x w4_t = w1[0];
  u32x w5_t = w1[1];
  u32x w6_t = w1[2];
  u32x w7_t = w1[3];
  u32x w8_t = w2[0];
  u32x w9_t = w2[1];
  u32x wa_t = w2[2];
  u32x wb_t = w2[3];
  u32x wc_t = w3[0];
  u32x wd_t = w3[1];
  u32x we_t = w3[2];
  u32x wf_t = w3[3];

  MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

  MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

  MD5_STEP (MD5_H, a, b, c, d, w5_t, MD5C20, MD5S20);
  MD5_STEP (MD5_H, d, a, b, c, w8_t, MD5C21, MD5S21);
  MD5_STEP (MD5_H, c, d, a, b, wb_t, MD5C22, MD5S22);
  MD5_STEP (MD5_H, b, c, d, a, we_t, MD5C23, MD5S23);
  MD5_STEP (MD5_H, a, b, c, d, w1_t, MD5C24, MD5S20);
  MD5_STEP (MD5_H, d, a, b, c, w4_t, MD5C25, MD5S21);
  MD5_STEP (MD5_H, c, d, a, b, w7_t, MD5C26, MD5S22);
  MD5_STEP (MD5_H, b, c, d, a, wa_t, MD5C27, MD5S23);
  MD5_STEP (MD5_H, a, b, c, d, wd_t, MD5C28, MD5S20);
  MD5_STEP (MD5_H, d, a, b, c, w0_t, MD5C29, MD5S21);
  MD5_STEP (MD5_H, c, d, a, b, w3_t, MD5C2a, MD5S22);
  MD5_STEP (MD5_H, b, c, d, a, w6_t, MD5C2b, MD5S23);
  MD5_STEP (MD5_H, a, b, c, d, w9_t, MD5C2c, MD5S20);
  MD5_STEP (MD5_H, d, a, b, c, wc_t, MD5C2d, MD5S21);
  MD5_STEP (MD5_H, c, d, a, b, wf_t, MD5C2e, MD5S22);
  MD5_STEP (MD5_H, b, c, d, a, w2_t, MD5C2f, MD5S23);

  MD5_STEP (MD5_I, a, b, c, d, w0_t, MD5C30, MD5S30);
  MD5_STEP (MD5_I, d, a, b, c, w7_t, MD5C31, MD5S31);
  MD5_STEP (MD5_I, c, d, a, b, we_t, MD5C32, MD5S32);
  MD5_STEP (MD5_I, b, c, d, a, w5_t, MD5C33, MD5S33);
  MD5_STEP (MD5_I, a, b, c, d, wc_t, MD5C34, MD5S30);
  MD5_STEP (MD5_I, d, a, b, c, w3_t, MD5C35, MD5S31);
  MD5_STEP (MD5_I, c, d, a, b, wa_t, MD5C36, MD5S32);
  MD5_STEP (MD5_I, b, c, d, a, w1_t, MD5C37, MD5S33);
  MD5_STEP (MD5_I, a, b, c, d, w8_t, MD5C38, MD5S30);
  MD5_STEP (MD5_I, d, a, b, c, wf_t, MD5C39, MD5S31);
  MD5_STEP (MD5_I, c, d, a, b, w6_t, MD5C3a, MD5S32);
  MD5_STEP (MD5_I, b, c, d, a, wd_t, MD5C3b, MD5S33);
  MD5_STEP (MD5_I, a, b, c, d, w4_t, MD5C3c, MD5S30);
  MD5_STEP (MD5_I, d, a, b, c, wb_t, MD5C3d, MD5S31);
  MD5_STEP (MD5_I, c, d, a, b, w2_t, MD5C3e, MD5S32);
  MD5_STEP (MD5_I, b, c, d, a, w9_t, MD5C3f, MD5S33);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

// Set up the HMAC-MD5 process
// The ipad and opad arrays can be retained to run multiple HMAC-MD5 processes
// without having to recalculate
// w0, w1, w2, w3 - contain up to 64 bytes of the HMAC key
// ipad, opad - contain the returned data to pass into the next call
void hmac_md5_pad_mangle (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[4], u32x opad[4])
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = MD5M_A;
  ipad[1] = MD5M_B;
  ipad[2] = MD5M_C;
  ipad[3] = MD5M_D;

  md5_transform_mangle (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = MD5M_A;
  opad[1] = MD5M_B;
  opad[2] = MD5M_C;
  opad[3] = MD5M_D;

  md5_transform_mangle (w0, w1, w2, w3, opad);
}

// Continue the HMAC-MD5 process
// It's up to the caller to add the final length and padding terminators
// hmac_md5_pad_mangle call, which can be used across multiple HMACs
// w0, w1, w2, w3 - contain up to 64 bytes of data to HMAC
// ipad, opad - should contain the output from the 
// digest - the 16-byte result of the HMAC
void hmac_md5_run_mangle (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[4], u32x opad[4], u32x digest[4])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];

  md5_transform_mangle (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 16) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];

  md5_transform_mangle (w0, w1, w2, w3, digest);
}

// Perfrom an HMAC-MD5 with the given key and using the domain constant as the
// data to HMAC
// in_key - the key to use (the user's password)
// key-len - the length of the key in bytes
// out_digest - returns the 16 byte result
void md5hmac_domain_mangle (u8 const *const in_key, const u32x key_len, u8 out_digest[16])
{
  u32 pos;

  // Data
  u32x data_buf[16];

  for (pos = 0; pos < domain_len; pos++)
  {
    ((u8 *) data_buf)[pos] = domain[pos];
  }
  for (pos = domain_len; pos < 64; pos++)
  {
    ((u8 *) data_buf)[pos] = 0;
  }

  // Key
  u32x key_buf[16];

  for (pos = 0; pos < key_len; pos++)
  {
    ((u8 *) key_buf)[pos] = in_key[pos];
  }
  for (pos = key_len; pos < 64; pos++)
  {
    ((u8 *) key_buf)[pos] = 0;
  }

  // Pads
  u32x ipad[4];
  u32x opad[4];

  hmac_md5_pad_mangle (key_buf, key_buf + 4, key_buf + 8, key_buf + 12, ipad, opad);

  // Loop (except this time we don't actually loop)
  append_0x80_2x4_VV (data_buf, data_buf + 4, domain_len);

  data_buf[14] = (64 + domain_len) * 8;

  hmac_md5_run_mangle (data_buf, data_buf + 4, data_buf + 8, data_buf + 12, ipad, opad, (u32x *) out_digest);
}

// Base64 encode a string
// base64_hash - the returned hahs
// len - the length of the input string
// base64_plain - the string to encode
// returns the length of the final encoding
u32 b64_encode_mangle (u8 * base64_hash, const u32 len, const u8 * base64_plain)
{
  u8 *out_ptr = (u8 *) base64_hash;
  u8 *in_ptr = (u8 *) base64_plain;
  u32 out_len;

  u32 i;

  // Encode the easy iniitial characters
  out_len = 0;
  for (i = 0; i < (len - 2); i += 3)
  {
    char out_val0 = b64_table[((in_ptr[0] >> 2) & 0x3f)];
    char out_val1 = b64_table[((in_ptr[0] << 4) & 0x30) | ((in_ptr[1] >> 4) & 0x0f)];
    char out_val2 = b64_table[((in_ptr[1] << 2) & 0x3c) | ((in_ptr[2] >> 6) & 0x03)];
    char out_val3 = b64_table[((in_ptr[2] >> 0) & 0x3f)];

    out_ptr[0] = out_val0 & 0x7f;
    out_ptr[1] = out_val1 & 0x7f;
    out_ptr[2] = out_val2 & 0x7f;
    out_ptr[3] = out_val3 & 0x7f;

    in_ptr += 3;
    out_ptr += 4;
    out_len += 4;
  }
  // Deal with the awkward terminating characters if there are any
  if (i == (len - 1))
  {
    // Input string has one hanging character
    char out_val0 = b64_table[((in_ptr[0] >> 2) & 0x3f)];
    char out_val1 = b64_table[((in_ptr[0] << 4) & 0x30)];

    out_ptr[0] = out_val0 & 0x7f;
    out_ptr[1] = out_val1 & 0x7f;
    out_ptr[2] = '=';
    out_ptr[3] = '=';

    in_ptr += 3;
    out_ptr += 4;
    out_len += 4;
  }
  if (i == (len - 2))
  {
    // Input string has two hanging characters
    char out_val0 = b64_table[((in_ptr[0] >> 2) & 0x3f)];
    char out_val1 = b64_table[((in_ptr[0] << 4) & 0x30) | ((in_ptr[1] >> 4) & 0x0f)];
    char out_val2 = b64_table[((in_ptr[1] << 2) & 0x3c)];

    out_ptr[0] = out_val0 & 0x7f;
    out_ptr[1] = out_val1 & 0x7f;
    out_ptr[2] = out_val2 & 0x7f;
    out_ptr[3] = '=';

    in_ptr += 3;
    out_ptr += 4;
    out_len += 4;
  }

  return out_len;
}

// Determine whether a given string contains non-alphanumeric values
// A non-alphanumeric is anything except a-z, A-Z, 0-9
// data - the string to check
// length - the length of the string
// returns true if there's a non-alphanumeric value, false o/w
bool containsnonalphanumeric_mangle (u8 * data, u32 length)
{
  bool nonalphanumeric;
  u32 pos;
  char check;
  u32 startingSize;

  nonalphanumeric = false;
  // Check each character individually
  for (pos = 0; (pos < length) && !nonalphanumeric; pos++)
  {
    check = data[pos];
    if (!((check >= 'a') && (check <= 'z')) && !((check >= 'A') && (check <= 'Z')) && !((check >= '0') && (check <= '9')) && !(check == '_'))
    {
      nonalphanumeric = true;
    }
  }

  return nonalphanumeric;
}

// Determine whether a string contains any value between a given range
// password - the string to check
// length - the length of the string to check
// start - the inclusive lower bound of the range to check between
// end - the inclusive upper bound of the range to check between
// returns true if the string contains a value that falls in the range
// returns false o/w
bool contains_mangle (u8 const *password, u32 length, u8 start, u8 end)
{
  bool doescontain = false;
  u32 pos;

  // Check each character individually
  for (pos = 0; (pos < length) && (doescontain == false); pos++)
  {
    if ((password[pos] >= start) && (password[pos] <= end))
    {
      doescontain = true;
    }
  }

  return doescontain;
}

// Rotate the characters in a string to the left by the given number of
// characters
// torotate - the string to rotate
// length - the length of the string to rotate
// steps - the number of steps to rotate to the left by
void rotate_string_mangle (u8 * torotate, u32 length, u32 steps)
{
  u8 scratch[64];
  u32 pos;

  // Create a rotated copy in a temporary buffer
  for (pos = 0; pos < length; pos++)
  {
    scratch[pos] = torotate[(pos + steps) % length];
  }

  // Copy the result back into the original buffer
  for (pos = 0; pos < length; pos++)
  {
    torotate[pos] = scratch[pos];
  }
}

// Perform the mangle operation on the string to be hashed
// w0, w1 - the string to be mangled
// in_len - the length of the string to be mangled
u32x mangle (u32x w0[4], u32x w1[4], const u32x in_len)
{
  u32x out_len = in_len;

  u32 digest[4];
  u32 data[8];
  u32 hash[8];
  u32 i;
  u32 size;
  u32 extrasize;
  u32 startingsize;
  bool nonalphanumeric;
  u32 extrapos;
  u8 next;

  hash[0] = w0[0];
  hash[1] = w0[1];
  hash[2] = w0[2];
  hash[3] = w0[3];
  hash[4] = w1[0];
  hash[5] = w1[1];
  hash[6] = w1[2];
  hash[7] = w1[3];

  // HMAC-MD5 the domain name using the password as the key
  md5hmac_domain_mangle ((u8 *) hash, in_len, (u8 *) digest);

  // Check whether the original password contains non-alphanumeric values
  nonalphanumeric = containsnonalphanumeric_mangle ((u8 *) hash, in_len);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  // Base64 encode the HMAC; this will be what we use to generate the password
  out_len = b64_encode_mangle ((u8 *) hash, 16, (u8 *) w0);

  out_len = 22;                 // b64 encoding will produce 24 bytes output, but last two will be "=="
  extrasize = 22;
  size = in_len + 2;

  // for (i = out_len; i < 32; i++) {
  // ((u8 *)hash)[i] = 0;
  // }

  startingsize = size - 4;
  startingsize = (startingsize < extrasize) ? startingsize : extrasize;

  // Transfer the intial portion for output
  for (i = 0; i < startingsize; i++)
  {
    ((u8 *) data)[i] = ((u8 *) hash)[i];
  }
  for (i = startingsize; i < 32; i++)
  {
    ((u8 *) data)[i] = 0;
  }

  extrapos = startingsize;

  // Add the extras
  // Capital letter
  next = (extrapos < extrasize) ? ((u8 *) hash)[extrapos] : 0;
  extrapos++;
  if (!contains_mangle ((u8 *) data, startingsize, 'A', 'Z'))
  {
    next = 'A' + (next % ('Z' - 'A' + 1));
  }
  ((u8 *) data)[startingsize] = next;
  startingsize++;

  // Lower case letter
  next = (extrapos < extrasize) ? ((u8 *) hash)[extrapos] : 0;
  extrapos++;
  if (!contains_mangle ((u8 *) data, startingsize, 'a', 'z'))
  {
    next = 'a' + (next % ('z' - 'a' + 1));
  }
  ((u8 *) data)[startingsize] = next;
  startingsize++;

  // Number
  next = (extrapos < extrasize) ? ((u8 *) hash)[extrapos] : 0;
  extrapos++;
  if (!contains_mangle ((u8 *) data, startingsize, '0', '9'))
  {
    next = '0' + (next % ('9' - '0' + 1));
  }
  ((u8 *) data)[startingsize] = next;
  startingsize++;

  // Non alphanumeric
  if (containsnonalphanumeric_mangle ((u8 *) data, startingsize) && nonalphanumeric)
  {
    next = (extrapos < extrasize) ? ((u8 *) hash)[extrapos] : 0;
    extrapos++;
  }
  else
  {
    next = '+';
  }
  ((u8 *) data)[startingsize] = next;
  startingsize++;

  // If there's no alphanumeric values in the original password
  // remove them from the result
  if (!nonalphanumeric)
  {
    for (i = 0; i < startingsize; i++)
    {
      if (containsnonalphanumeric_mangle (((u8 *) data) + i, 1))
      {
        next = (extrapos < extrasize) ? ((u8 *) hash)[extrapos] : 0;
        extrapos++;
        next = 'A' + (next % ('Z' - 'A' + 1));
        ((u8 *) data)[i] = next;
      }
    }
  }

  // Rotate the result to ranomise where the non-alphanumerics are
  next = (extrapos < extrasize) ? ((u8 *) hash)[extrapos] : 0;
  rotate_string_mangle ((u8 *) data, startingsize, next);
  ((u8 *) data)[startingsize] = 0;

  out_len = startingsize;

  // Copy th result into the output buffer
  w0[0] = data[0];
  w0[1] = data[1];
  w0[2] = data[2];
  w0[3] = data[3];
  w1[0] = data[4];
  w1[1] = data[5];
  w1[2] = data[6];
  w1[3] = data[7];

  return (out_len);
}
