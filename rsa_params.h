#ifndef _RSA_PARAMS_H
#define _RSA_PARAMS_H

#include <stdbool.h>
#include <openssl/bn.h>

#include "integer_group.h"
#include "util.h"

typedef struct rsa_params* RsaParams;
typedef const struct rsa_params* const_RsaParams;

/**
 * Generate a new set of RSA parameters where
 * the primes p,q are supposed to be prime_bits long
 */
RsaParams RsaParams_New(int prime_bits);

/**
 * Read RsaParams from a file
 */
RsaParams RsaParams_Read(const char* filename);

void RsaParams_Free(RsaParams params);

/**
 * Write parameters to a file.
 * Returns 1 on success, 0 on failure.
 */
int RsaParams_Serialize(const_RsaParams params, FILE* file);

/**
 * Read parameters from a file.
 * Returns NULL on failure.
 */
RsaParams RsaParams_Unserialize(FILE* file);

/**
 * Get length (in bytes) of a CA signature
 */
int RsaParams_CaSignatureLength(const_RsaParams params);

/**
 * Have the CA sign a msg. sig must point to
 * at least CaSignatureLength bytes of memory
 */
bool RsaParams_CaSign(const_RsaParams params, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len);

/**
 * Verify a CA signature on a msg
 */
bool RsaParams_CaVerify(const_RsaParams params, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len);

EVP_PKEY* RsaParams_GetCaPrivateKey(const_RsaParams params);
EVP_PKEY* RsaParams_GetCaPublicKey(const_RsaParams params);
EVP_PKEY* RsaParams_GetEaPrivateKey(const_RsaParams params);
EVP_PKEY* RsaParams_GetEaPublicKey(const_RsaParams params);

/* Same as CA versions above */
int RsaParams_EaSignatureLength(const_RsaParams params);
bool RsaParams_EaSign(const_RsaParams params, unsigned char* sig, int* sig_len,
    const unsigned char* msg, int msg_len);
bool RsaParams_EaVerify(const_RsaParams params, const unsigned char* sig, int sig_len,
    const unsigned char* msg, int msg_len);

/*
 * If k=prime_bits, return true if value is in the range
 * [2^k, ..., 2^{k+1})
 */
bool RsaParams_InRange(const_RsaParams params, const BIGNUM* value);

/**
 * Get largest allowable delta value for our RSA keygen
 * protocol.
 */
int RsaParams_GetDeltaMax(const_RsaParams params);

/**
 * Get prime size
 */
int RsaParams_GetModulusBits(const_RsaParams params);

IntegerGroup RsaParams_GetGroup(const_RsaParams params);

BN_CTX* RsaParams_GetCtx(const_RsaParams params);

/**
 * If k=modulus_bits, let l = k/2 return a value in the range
 * [2^l, ..., 2^{l+1})
 */
BIGNUM* RsaParams_RandomLargeValue(const_RsaParams params);

#endif
