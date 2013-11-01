#ifndef _GEN_KEYS_H
#define _GEN_KEYS_H

#include <stdbool.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

#include "dsa_params.h"
#include "rsa_params.h"
#include "util.h"

/**
 * Benchmarking methods for generating keys
 * WITHOUT using the verifiable protocol.
 */

X509* GenerateDsa(DsaParams params);

X509* GenerateRsa(RsaParams params);


#endif
