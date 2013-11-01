#ifndef _DSA_EA_H
#define _DSA_EA_H

#include "dsa_params.h"
#include "util.h"

typedef struct dsa_ea* DsaEa;
typedef const struct dsa_ea* const_DsaEa;

/**
 * Create a new DSA Entropy Authority
 */
DsaEa DsaEa_New(DsaParams params);
void DsaEa_Free(DsaEa ea);

bool DsaEa_GetEntropyResponse(DsaEa ea, const EC_POINT* commit_x, 
    BIGNUM* x_prime, BIGNUM* rand_x_prime);

bool DsaEa_SetCertRequest(DsaEa ea, const BIGNUM* rand_a, X509_REQ* req);

bool DsaEa_GetCertResponse(DsaEa ea, X509** cert);

#endif
