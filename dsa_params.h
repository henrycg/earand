#ifndef _DSA_PARAMS_H
#define _DSA_PARAMS_H

#include <stdbool.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "util.h"

typedef struct dsa_params* DsaParams;
typedef const struct dsa_params* const_DsaParams;

DsaParams DsaParams_New(const char* curve_name);
DsaParams DsaParams_Read(const char* filename);

void DsaParams_Free(DsaParams params);

/**
 * Write parameters to a file.
 * Returns 1 on success, 0 on failure.
 */
int DsaParams_Serialize(const_DsaParams params, FILE* file);

/**
 * Read parameters from a file.
 * Returns NULL on failure.
 */
DsaParams DsaParams_Unserialize(FILE* file);

/**
 * Get length (in bytes) of a CA signature
 */
int DsaParams_CaSignatureLength(const_DsaParams params);

/**
 * Have the CA sign a msg. sig must point to
 * at least CaSignatureLength bytes of memory
 */
bool DsaParams_CaSign(const_DsaParams params, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len);

/**
 * Verify a CA signature on a msg
 */
bool DsaParams_CaVerify(const_DsaParams params, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len);

EVP_PKEY* DsaParams_GetCaPrivateKey(const_DsaParams params);
EVP_PKEY* DsaParams_GetCaPublicKey(const_DsaParams params);
EVP_PKEY* DsaParams_GetEaPrivateKey(const_DsaParams params);
EVP_PKEY* DsaParams_GetEaPublicKey(const_DsaParams params);

/* Same as CA versions above */
int DsaParams_EaSignatureLength(const_DsaParams params);
bool DsaParams_EaSign(const_DsaParams params, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len);
bool DsaParams_EaVerify(const_DsaParams params, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len);

BIGNUM* DsaParams_RandomExponent(const_DsaParams params);
EC_POINT* DsaParams_MultiplyG(const_DsaParams params, const BIGNUM* exp);
EC_POINT* DsaParams_MultiplyH(const_DsaParams params, const BIGNUM* exp);
EC_POINT* DsaParams_Multiply(const_DsaParams params, const EC_POINT* point, 
    const BIGNUM* exp);
EC_POINT* DsaParams_Add(const_DsaParams params, const EC_POINT* a, const EC_POINT* b);
void DsaParams_Invert(const_DsaParams params, EC_POINT* a);

EC_POINT* DsaParams_Commit(const_DsaParams params, const BIGNUM* v, const BIGNUM* r);

unsigned char* DsaParams_PointToString(const_DsaParams params, const EC_POINT* point, int* buf_len);

/**
 *Getters
 */
EC_GROUP* DsaParams_GetCurve(const_DsaParams params);
const EC_POINT* DsaParams_GetG(const_DsaParams params);
const EC_POINT* DsaParams_GetH(const_DsaParams params);
const BIGNUM* DsaParams_GetQ(const_DsaParams params);
BN_CTX* DsaParams_GetCtx(DsaParams params);

#endif
