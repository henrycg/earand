#ifndef _RSA_DEVICE_H
#define _RSA_DEVICE_H

#include <stdbool.h>
#include <openssl/bn.h>
#include <openssl/x509.h>

#include "product_proof.h"
#include "rsa_params.h"
#include "util.h"

typedef struct rsa_device* RsaDevice;
typedef const struct rsa_device* const_RsaDevice;

/**
 * Allocate a new device for RSA keygen protocol
 */
RsaDevice RsaDevice_New(RsaParams params);
void RsaDevice_Free(RsaDevice d);

/**
 * This function runs the whole keygen protocol, 
 * including interaction with EA and CA servers.
 * It returns an X509 certificate signed by the CA.
 */
X509* RsaDevice_RunProtocol(RsaDevice d, bool ca_sign,
    const char* ea_hostname, int ea_port,
    const char* ca_hostname, int ca_port);

/**********************************************/
/* These are private methods that you shouldn't 
 * need to use.
 */
 
bool RsaDevice_GenEntropyRequest(RsaDevice d,
    BIGNUM* commit_x, BIGNUM* commit_y);

// Free x_prime and y_prime after calling.
bool RsaDevice_SetEntropyResponse(RsaDevice d, 
    const BIGNUM* x_prime, const BIGNUM* y_prime);

bool RsaDevice_GenEaSigningRequest(RsaDevice d,
    X509_REQ* req, BIGNUM* delta_x, BIGNUM* delta_y,
    BIGNUM* rand_n, ProductEvidence* ev);

bool RsaDevice_SetEaCertResponse(RsaDevice d, X509* cert);

bool RsaDevice_GenCaCertRequest(RsaDevice d, X509** ea_cert);

bool RsaDevice_SetCaCertResponse(RsaDevice d, X509* ca_cert);

/* Getters */
const BIGNUM* RsaDevice_GetX(const_RsaDevice rsa);
const BIGNUM* RsaDevice_GetY(const_RsaDevice rsa);
const BIGNUM* RsaDevice_GetXPrime(const_RsaDevice rsa);
const BIGNUM* RsaDevice_GetYPrime(const_RsaDevice rsa);
const BIGNUM* RsaDevice_GetP(const_RsaDevice rsa);
const BIGNUM* RsaDevice_GetQ(const_RsaDevice rsa);
const BIGNUM* RsaDevice_GetN(const_RsaDevice rsa);

#endif
