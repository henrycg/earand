#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>

#include "rsa_device.h"
#include "dsa_device.h"
#include "gen_keys.h"

#define MODE_RSA "rsa"
#define MODE_DSA "dsa"
#define MODE_RSA_NOVER "rsa-nover"
#define MODE_DSA_NOVER "dsa-nover"

int main(int argc, char* argv[])
{
#ifdef DEBUG
  fprintf(stderr, "Using debug mode... DO NOT use for performance testing.\n");
#endif

  if(argc != 7) {
    fatal("Usage: %s (%s|%s|%s|%s) params_file ea_host ea_port ca_host ca_port", 
        argv[0], MODE_RSA, MODE_RSA_NOVER, MODE_DSA, MODE_DSA_NOVER);
  }

  X509* cert = NULL;
  
  if(strcmp(argv[1], MODE_RSA) == 0) {
    RsaParams params = RsaParams_Read(argv[2]);
    RsaDevice device = RsaDevice_New(params);

    cert = RsaDevice_RunProtocol(device, false,
      argv[3], atoi(argv[4]),
      argv[5], atoi(argv[6]));

    RsaDevice_Free(device);
    RsaParams_Free(params);
  } else if(strcmp(argv[1], MODE_DSA) == 0) {
    DsaParams params = DsaParams_Read(argv[2]);
    DsaDevice device = DsaDevice_New(params);

    cert = DsaDevice_RunProtocol(device, false,
      argv[3], atoi(argv[4]),
      argv[5], atoi(argv[6]));

    DsaDevice_Free(device);
    DsaParams_Free(params);
  } else if(strcmp(argv[1], MODE_RSA_NOVER) == 0) {
    RsaParams params = RsaParams_Read(argv[2]);
    cert = GenerateRsa(params);
    RsaParams_Free(params);
  } else if(strcmp(argv[1], MODE_DSA_NOVER) == 0) {
    DsaParams params = DsaParams_Read(argv[2]);
    cert = GenerateDsa(params);
    DsaParams_Free(params);
  } else {
    fatal("Invalid mode: %s", argv[1]);
  }

  CHECK_CALL(cert);

  X509_print_fp(stderr, cert);
  puts("");
  X509_free(cert);

  // Clean up OpenSSL junk
  ERR_remove_state(0);
  ERR_free_strings();
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  return EXIT_SUCCESS;
}
