#include <stdbool.h>

#include <openssl/pem.h>

#include "integer_group.h"
#include "rsa_params.h"
#include "util.h"

static const char str_modulus_bits[] = "modulus_bits";

static void ReadPublicKey(EVP_PKEY** dst, const char* filename);
static void ReadPrivateKey(EVP_PKEY** dst, const char* filename);
static bool Sign(EVP_PKEY* key, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len);
static bool Verify(EVP_PKEY* key, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len);

struct rsa_params {
  int modulus_bits;
  IntegerGroup group;
  BN_CTX* ctx;

  EVP_PKEY* ca_public_key;
  EVP_PKEY* ca_private_key;

  EVP_PKEY* ea_public_key;
  EVP_PKEY* ea_private_key;
};

RsaParams RsaParams_New(int modulus_bits)
{
  CHECK_CALL(modulus_bits > 10);

  RsaParams params = safe_malloc(sizeof(*params));
  params->modulus_bits = modulus_bits;
  params->group = IntegerGroup_Generate(modulus_bits+100);
  CHECK_CALL(params->ctx = BN_CTX_new());

  ReadPublicKey(&(params->ca_public_key), CA_PUBLIC_KEY_FILE);
  ReadPrivateKey(&(params->ca_private_key), CA_PRIVATE_KEY_FILE);

  ReadPublicKey(&(params->ea_public_key), EA_PUBLIC_KEY_FILE);
  ReadPrivateKey(&(params->ea_private_key), EA_PRIVATE_KEY_FILE);
  
  return params;
}

RsaParams RsaParams_Read(const char* filename)
{
  // Read common system parameters;
  FILE* fp = fopen(filename, "r");
  CHECK_CALL(fp);

  RsaParams params = RsaParams_Unserialize(fp);
  CHECK_CALL(params);
  fclose(fp);

  return params;
}

void RsaParams_Free(RsaParams params) 
{
  IntegerGroup_Free(params->group);
  
  EVP_PKEY_free(params->ca_public_key);
  EVP_PKEY_free(params->ca_private_key);

  EVP_PKEY_free(params->ea_public_key);
  EVP_PKEY_free(params->ea_private_key);

  BN_CTX_free(params->ctx);

  free(params);
}

int RsaParams_Serialize(const_RsaParams params, FILE* file)
{
  if(!((fprintf(file, "%s", str_modulus_bits) == (sizeof(str_modulus_bits)-1)) &&
    putc(':', file) &&
    fprintf(file, "%d", params->modulus_bits) &&
    putc('\n', file))) return false;

  if(!IntegerGroup_Serialize(params->group, file))
    return false;

  if(!PEM_write_PUBKEY(file, params->ca_public_key))
    return false;

  if(!PEM_write_PrivateKey(file, params->ca_private_key, NULL, NULL, 0, 0, NULL))
    return false;

  if(!PEM_write_PUBKEY(file, params->ea_public_key))
    return false;

  if(!PEM_write_PrivateKey(file, params->ea_private_key, NULL, NULL, 0, 0, NULL))
    return false;

  return true;
}

RsaParams RsaParams_Unserialize(FILE* file)
{
  RsaParams params = safe_malloc(sizeof(*params));
  CHECK_CALL(params->ctx = BN_CTX_new());

  // Read the "modulus_bits" tag
  for(const char *p = str_modulus_bits; *p; p++) {
    int c = getc(file);
    if(c < 0 || c != *p) {
      free(params);
      return NULL;
    }
  }

  if(fscanf(file, ":%d\n", &(params->modulus_bits)) != 1) {
    free(params);
    return NULL;
  }

  params->group = IntegerGroup_Unserialize(file);
  if(!params->group) {
    free(params);
    return NULL;
  }

  if(!((params->ca_public_key = PEM_read_PUBKEY(file, NULL, NULL, NULL)) &&
    (params->ca_private_key = PEM_read_PrivateKey(file, NULL, NULL, NULL)) &&
    (params->ea_public_key = PEM_read_PUBKEY(file, NULL, NULL, NULL)) &&
    (params->ea_private_key = PEM_read_PrivateKey(file, NULL, NULL, NULL)))) {
    free(params);
    return NULL;
  }

  return params;
}

int RsaParams_CaSignatureLength(const_RsaParams params)
{
  return EVP_PKEY_size(params->ca_public_key);
}

bool RsaParams_CaSign(const_RsaParams params, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len)
{
  return Sign(params->ca_private_key, sig, sig_len, msg, msg_len);
}

bool RsaParams_CaVerify(const_RsaParams params, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len)
{
  return Verify(params->ca_public_key, sig, sig_len, msg, msg_len);
}

EVP_PKEY* RsaParams_GetCaPrivateKey(const_RsaParams params)
{
  return params->ca_private_key;
}

EVP_PKEY* RsaParams_GetCaPublicKey(const_RsaParams params)
{
  return params->ca_public_key;
}

EVP_PKEY* RsaParams_GetEaPrivateKey(const_RsaParams params)
{
  return params->ea_private_key;
}

EVP_PKEY* RsaParams_GetEaPublicKey(const_RsaParams params)
{
  return params->ea_public_key;
}

int RsaParams_EaSignatureLength(const_RsaParams params)
{
  return EVP_PKEY_size(params->ea_public_key);
}

bool RsaParams_EaSign(const_RsaParams params, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len)
{
  return Sign(params->ea_private_key, sig, sig_len, msg, msg_len);
}

bool RsaParams_EaVerify(const_RsaParams params, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len)
{
  return Verify(params->ea_public_key, sig, sig_len, msg, msg_len);
}

bool RsaParams_InRange(const_RsaParams params, const BIGNUM* value)
{
  BIGNUM* min = BN_new();
  BIGNUM* max = BN_new();

  const int prime_bits = RsaParams_GetModulusBits(params)/2;

  // min = 2^k
  BN_one(min); 
  CHECK_CALL(BN_lshift(min, min, prime_bits));

  // max = 2^{k+1}
  BN_one(max); 
  CHECK_CALL(BN_lshift(max, max, prime_bits+1));
    
  bool result = (BN_cmp(min, value) == -1) &&
   ( BN_cmp(value, max) == -1);

  BN_free(min);
  BN_free(max);

  return result;
}

int RsaParams_GetDeltaMax(const_RsaParams params)
{
  // According to Juels paper, the
  // probability that we will fail to find a prime
  // in range [r, r+l) is at most:
  //    exp(-lambda)
  // where
  //    e is the RSA encryption exponent (65537)!!!!
  //    l = lambda * ln(r) * 2e / (e-1)
  //
  // Taking lambda = 80 and (2e / (e-1)) ~ 2,
  // we need 160 * prime_bits
  return (160 * (params->modulus_bits/2));
}

int RsaParams_GetModulusBits(const_RsaParams params)
{
  return params->modulus_bits;
}

IntegerGroup RsaParams_GetGroup(const_RsaParams params)
{
  return params->group;
}

BN_CTX* RsaParams_GetCtx(const_RsaParams params)
{
  return params->ctx;
}

BIGNUM* RsaParams_RandomLargeValue(const_RsaParams params) 
{
  BIGNUM *result = BN_new();

  CHECK_CALL(result);
  CHECK_CALL(BN_rand(result, (params->modulus_bits/2)+1, 0, 0));

  return result;
}

static void ReadPublicKey(EVP_PKEY** dst, const char* filename)
{
  FILE* fp = fopen(filename, "r");
  CHECK_CALL(fp);
  CHECK_CALL((*dst) = PEM_read_PUBKEY(fp, NULL, NULL, NULL));
  CHECK_CALL(*dst);
  fclose(fp);
}

static void ReadPrivateKey(EVP_PKEY** dst, const char* filename)
{
  FILE* fp = fopen(filename, "r");
  CHECK_CALL(fp);
  CHECK_CALL((*dst) = PEM_read_PrivateKey(fp, NULL, NULL, NULL));
  CHECK_CALL(*dst);
  fclose(fp);
}

bool Sign(EVP_PKEY* key, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len)
{
  EVP_MD_CTX ctx;
  EVP_SignInit(&ctx, EVP_sha1());

  bool retval = EVP_SignUpdate(&ctx, msg, msg_len) &&
    EVP_SignFinal(&ctx, sig, (unsigned int*)sig_len, key);

  EVP_MD_CTX_cleanup(&ctx);

  return retval;
}

bool Verify(EVP_PKEY* key, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len)
{
  EVP_MD_CTX ctx;
  bool retval = EVP_VerifyInit(&ctx, EVP_sha1()) &&
    EVP_VerifyUpdate(&ctx, msg, msg_len) &&
    (EVP_VerifyFinal(&ctx, sig, sig_len, key) == 1);

  EVP_MD_CTX_cleanup(&ctx);

  return retval;
}
