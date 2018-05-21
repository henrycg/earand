#ifndef _DSA_DEVICE_H
#define _DSA_DEVICE_H

#include <stdbool.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

#include "dsa_params.h"
#include "pedersen_proof.h"
#include "util.h"

typedef struct dsa_device* DsaDevice;
typedef const struct dsa_device* const_DsaDevice;

/**
 * Allocate a new device for RSA keygen protocol
 */
DsaDevice DsaDevice_New(DsaParams params);
void DsaDevice_Free(DsaDevice d);

/**
 * This function runs the whole keygen protocol, 
 * including interaction with EA and CA servers.
 * It returns an X509 certificate signed by the CA.
 */
X509* DsaDevice_RunProtocol(DsaDevice d, bool ca_sign,
    const char* ea_hostname, int ea_port,
    const char* ca_hostname, int ca_port);

/**********************************************/
/* These are private methods that you shouldn't 
 * need to use.
 */
 
bool DsaDevice_GenEntropyRequest(DsaDevice d, EC_POINT** commit_x);

bool DsaDevice_SetEntropyResponse(DsaDevice d, const BIGNUM* x_prime);

bool DsaDevice_GenEaCertRequest(DsaDevice d, PedersenEvidence* ev, X509_REQ** req);

bool DsaDevice_SetEaCertResponse(DsaDevice d, X509* cert);

bool DsaDevice_GenCaCertRequest(DsaDevice d, X509** cert);

bool DsaDevice_SetCaCertResponse(DsaDevice d, X509* cert);

#endif
