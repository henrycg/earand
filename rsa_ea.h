#ifndef _RSA_EA_H
#define _RSA_EA_H

#include "product_proof.h"
#include "rsa_params.h"
#include "util.h"

typedef struct rsa_ea* RsaEa;
typedef const struct rsa_ea* const_RsaEa;

/**
 * Create a new RSA Entropy Authority
 */
RsaEa RsaEa_New(RsaParams params, 
    const BIGNUM* commit_x, const BIGNUM* commit_y);
void RsaEa_Free(RsaEa ea);

/**
 * Return entropy to the device.
 * x_prime and y_prime are the return values and they
 * must be allocated using BN_new()
 */
void RsaEa_GenEntropyResponse(RsaEa ea, BIGNUM* x_prime, BIGNUM* y_prime);

/**
 * Give the EA the device's signature request values.
 * open_n is the randomness used to commit to the RSA modulus n
 */
bool RsaEa_SetCertRequest(RsaEa ea, X509_REQ* req, const BIGNUM* delta_x, 
    const BIGNUM* delta_y, const BIGNUM* rand_n, 
    const ProductEvidence ev);

/**
 * Get the EA's signature on the device's modulus
 */
bool RsaEa_GetCertResponse(RsaEa ea, X509** cert);

#endif
