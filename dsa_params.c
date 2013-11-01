#include <stdbool.h>

#include <openssl/pem.h>

#include "dsa_params.h"
#include "util.h"

static const char str_curve_name[] = "curve_name";

static void ReadPublicKey(EVP_PKEY** dst, const char* filename);
static void ReadPrivateKey(EVP_PKEY** dst, const char* filename);
static bool Sign(EVP_PKEY* key, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len);
static bool Verify(EVP_PKEY* key, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len);

struct dsa_params {
  EC_GROUP* group;
  BIGNUM* order;
  BN_CTX* ctx;

  EC_POINT* commit_g;
  EC_POINT* commit_h;

  EVP_PKEY* ca_public_key;
  EVP_PKEY* ca_private_key;

  EVP_PKEY* ea_public_key;
  EVP_PKEY* ea_private_key;
};

void SetupCurve(DsaParams params, const char* curve_name)
{
  //const int nid = OBJ_txt2nid("secp224r1");
  const int nid = OBJ_txt2nid(curve_name);
  CHECK_CALL(nid > 0);
  CHECK_CALL(params->group = EC_GROUP_new_by_curve_name(nid));
  CHECK_CALL(params->ctx = BN_CTX_new());

  CHECK_CALL(params->commit_g = EC_POINT_dup(
        EC_GROUP_get0_generator(params->group), params->group));
  CHECK_CALL(params->commit_h = EC_POINT_new(params->group));

  // For h value just pick some random constant point
  BIGNUM* tmp = BN_new();
  CHECK_CALL(tmp);
  BN_one(tmp);
  BN_add_word(tmp, 5);

  do {
    CHECK_CALL(params->commit_h);
    BN_add_word(tmp, 1);
  } while(!(EC_POINT_set_compressed_coordinates_GFp(params->group, params->commit_h, tmp, 1, params->ctx)
      && EC_POINT_is_on_curve(params->group, params->commit_h, params->ctx)));
  BN_clear_free(tmp);
}


DsaParams DsaParams_New(const char* curve_name)
{
  DsaParams params = safe_malloc(sizeof(*params));
  SetupCurve(params, curve_name);
  CHECK_CALL(params->order = BN_new());
  CHECK_CALL(EC_GROUP_get_order(params->group, params->order, params->ctx));

  ReadPublicKey(&(params->ca_public_key), CA_PUBLIC_KEY_FILE);
  ReadPrivateKey(&(params->ca_private_key), CA_PRIVATE_KEY_FILE);

  ReadPublicKey(&(params->ea_public_key), EA_PUBLIC_KEY_FILE);
  ReadPrivateKey(&(params->ea_private_key), EA_PRIVATE_KEY_FILE);
  
  return params;
}

DsaParams DsaParams_Read(const char* filename) 
{
  // Read common system parameters;
  FILE* fp = fopen(filename, "r");
  CHECK_CALL(fp);

  DsaParams params = DsaParams_Unserialize(fp);
  CHECK_CALL(params);
  fclose(fp);

  return params;
}

void DsaParams_Free(DsaParams params) 
{
  EC_POINT_clear_free(params->commit_g);
  EC_POINT_clear_free(params->commit_h);
  EC_GROUP_clear_free(params->group);
  BN_clear_free(params->order);
  BN_CTX_free(params->ctx);
  
  EVP_PKEY_free(params->ca_public_key);
  EVP_PKEY_free(params->ca_private_key);

  EVP_PKEY_free(params->ea_public_key);
  EVP_PKEY_free(params->ea_private_key);

  free(params);
}

int DsaParams_Serialize(const_DsaParams params, FILE* file)
{
  int nid = EC_GROUP_get_curve_name(params->group);
  CHECK_CALL(nid > 0);
  const char* curve_name = OBJ_nid2sn(nid);
  CHECK_CALL(curve_name);
  if(!((fprintf(file, "%s", str_curve_name) == (sizeof(str_curve_name)-1)) &&
    putc(':', file) &&
    fprintf(file, "%s", curve_name) &&
    putc('\n', file))) return false;

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

DsaParams DsaParams_Unserialize(FILE* file)
{
  DsaParams params = safe_malloc(sizeof(*params));

  // Read the "curve_name" tag
  for(const char *p = str_curve_name; *p; p++) {
    int c = getc(file);
    if(c < 0 || c != *p) {
      free(params);
      return NULL;
    }
  }

  char curve_name[1024];

  if(!(1 == fscanf(file, ":%s\n", curve_name))) return NULL;

  SetupCurve(params, curve_name);
  CHECK_CALL(params->order = BN_new());
  CHECK_CALL(EC_GROUP_get_order(params->group, params->order, params->ctx));

  if(!((params->ca_public_key = PEM_read_PUBKEY(file, NULL, NULL, NULL)) &&
    (params->ca_private_key = PEM_read_PrivateKey(file, NULL, NULL, NULL)) &&
    (params->ea_public_key = PEM_read_PUBKEY(file, NULL, NULL, NULL)) &&
    (params->ea_private_key = PEM_read_PrivateKey(file, NULL, NULL, NULL)))) {
    free(params);
    return NULL;
  }

  return params;
}

int DsaParams_CaSignatureLength(const_DsaParams params)
{
  return EVP_PKEY_size(params->ca_public_key);
}

bool DsaParams_CaSign(const_DsaParams params, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len)
{
  return Sign(params->ca_private_key, sig, sig_len, msg, msg_len);
}

bool DsaParams_CaVerify(const_DsaParams params, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len)
{
  return Verify(params->ca_public_key, sig, sig_len, msg, msg_len);
}

EVP_PKEY* DsaParams_GetCaPrivateKey(const_DsaParams params)
{
  return params->ca_private_key;
}

EVP_PKEY* DsaParams_GetCaPublicKey(const_DsaParams params)
{
  return params->ca_public_key;
}

EVP_PKEY* DsaParams_GetEaPrivateKey(const_DsaParams params)
{
  return params->ea_private_key;
}

EVP_PKEY* DsaParams_GetEaPublicKey(const_DsaParams params)
{
  return params->ea_public_key;
}
int DsaParams_EaSignatureLength(const_DsaParams params)
{
  return EVP_PKEY_size(params->ea_public_key);
}

bool DsaParams_EaSign(const_DsaParams params, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len)
{
  return Sign(params->ea_private_key, sig, sig_len, msg, msg_len);
}

bool DsaParams_EaVerify(const_DsaParams params, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len)
{
  return Verify(params->ea_public_key, sig, sig_len, msg, msg_len);
}

BIGNUM* DsaParams_RandomExponent(const_DsaParams params)
{
  BIGNUM *result = BN_new();

  CHECK_CALL(result);
  CHECK_CALL(BN_rand_range(result, params->order));

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

EC_POINT* DsaParams_Commit(const_DsaParams params, const BIGNUM* v, const BIGNUM* r)
{
  EC_POINT* res = EC_POINT_new(params->group);
  CHECK_CALL(res);

  const EC_POINT* points[2];
  const BIGNUM* muls[2];

  points[0] = params->commit_g;
  points[1] = params->commit_h;

  muls[0] = v;
  muls[1] = r;

  // Commit = g^v h^r
  CHECK_CALL(EC_POINTs_mul(params->group, res, NULL, 2, points, muls, params->ctx));
  return res;
}

EC_GROUP* DsaParams_GetCurve(const_DsaParams params)
{
  return params->group;
}

const EC_POINT* DsaParams_GetG(const_DsaParams params)
{
  return params->commit_g;
}

const EC_POINT* DsaParams_GetH(const_DsaParams params)
{
  return params->commit_h;
}

const BIGNUM* DsaParams_GetQ(const_DsaParams params)
{
  return params->order;
}

BN_CTX* DsaParams_GetCtx(DsaParams params)
{
  return params->ctx;
}

unsigned char* DsaParams_PointToString(const_DsaParams params, const EC_POINT* point, int* buf_len)
{
  *buf_len = (int)EC_POINT_point2oct(params->group, 
      point, POINT_CONVERSION_UNCOMPRESSED,
      NULL, 0, params->ctx);

  unsigned char* buf = safe_malloc(*buf_len * sizeof(unsigned char));

  CHECK_CALL(*buf_len == EC_POINT_point2oct(params->group, 
      point, POINT_CONVERSION_UNCOMPRESSED,
      buf, *buf_len, params->ctx));

  return buf;
}

EC_POINT* DsaParams_MultiplyG(const_DsaParams params, const BIGNUM* exp)
{
  BIGNUM* zero = BN_new();
  CHECK_CALL(zero);
  BN_zero(zero);

  EC_POINT* ret = DsaParams_Commit(params, exp, zero);
  BN_free(zero);

  return ret;
}

EC_POINT* DsaParams_MultiplyH(const_DsaParams params, const BIGNUM* exp)
{
  BIGNUM* zero = BN_new();
  CHECK_CALL(zero);
  BN_zero(zero);

  EC_POINT* ret = DsaParams_Commit(params, zero, exp);
  BN_free(zero);

  return ret;
}


EC_POINT* DsaParams_Add(const_DsaParams params, const EC_POINT* a, const EC_POINT* b)
{
  EC_POINT* res = EC_POINT_new(params->group);
  CHECK_CALL(res);
  CHECK_CALL(EC_POINT_add(params->group, res, a, b, params->ctx));
  return res;
}
