/***************************************************************************
 *   Copyright (C) 2007 by Michael Fischer                                 *
 *   fischer-michael@cs.yale.edu                                           *
 *                                                                         *
 *   This file is part of Heap.                                            *
 *									   *
 *   Heap is free software; you can redistribute it and/or modify	   *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or	   *
 *   any later version.							   *
 *									   *
 *   Heap is distributed in the hope that it will be useful,		   *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of	   *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the	   *
 *   GNU General Public License for more details.			   *
 *									   *
 *   You should have received a copy of the GNU General Public License	   *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

struct ca_request_data {
  int client_type;
  X509* cert;
}; 


#ifdef DEBUG
#define ASSERT(a) CHECK_CALL(a)
#else  
#define ASSERT(a) 
#endif

#define CHECK_CALL(a) do { \
   if(!(a)) { \
     fatal("File: %s, Line: %d, Function: %s\n",  __FILE__,  __LINE__, #a); \
   } \
   } while(0);

// Constants used throughout
#define CA_CERTIFICATE_FILE   "keys/ca_cert.pem"
#define CA_PUBLIC_KEY_FILE    "keys/ca_pub.pem"
#define CA_PRIVATE_KEY_FILE   "keys/ca_priv.pem"
#define EA_CERTIFICATE_FILE   "keys/ea_cert.pem"
#define EA_PUBLIC_KEY_FILE    "keys/ea_pub.pem"
#define EA_PRIVATE_KEY_FILE   "keys/ea_priv.pem"

// Strings used in transmitting data over wire
#define RSA_CLIENT            1
#define DSA_CLIENT            2

#define STRING_COMMIT_X       "cx"
#define STRING_COMMIT_Y       "cy"
#define STRING_X_PRIME        "xp"
#define STRING_Y_PRIME        "yp"
#define STRING_RAND_A         "ra"
#define STRING_RAND_X_PRIME   "rxp"
#define STRING_DELTA_X        "dx"
#define STRING_DELTA_Y        "dy"
#define STRING_MODULUS        "n"
#define STRING_MODULUS_RAND   "rand_n"

static const int RsaEncryptionExponent = 65537;

/**
 * malloc/realloc but exit() if there
 * is no memory left
 */
void* safe_malloc( size_t size );
void* safe_realloc( void *ptr, size_t size );

/**
 * Print a message to stderr using fprintf,
 * append a newline, and exit with an error code
 */
void fatal( const char* format, ... );

/**
 * Print a BIGNUM out to a file
 */
int WriteOneBignum(const char *tag, int tag_len, FILE* file, const BIGNUM* bn);

/**
 * Print a EC_POINT out to a file
 */
int WriteOnePoint(const char *tag, int tag_len, FILE* file, 
    const EC_GROUP* g, const EC_POINT* ec, BN_CTX *ctx);

/**
 * Read a BIGNUM in from a file
 */
int ReadOneBignum(BIGNUM **bn, FILE* file, const char str[]);

/**
 * Read an EC_POINT in from a file
 */
int ReadOnePoint(EC_POINT **ec, EC_GROUP* g, FILE* file, const char *tag, BN_CTX* ctx);

/**
 * Create read/write file descriptors and FILE* pointers
 * from an open SSL connection
 */
void SetupFileDescriptors(SSL* ssl, int* rfd, FILE** rfp,
    int* wfd, FILE** wfp);

/**
 * Convert to base64
 */
unsigned char* ToBase64(const unsigned char* msg, int msg_len, int* bytes_written);
unsigned char* FromBase64(const unsigned char* base, int base_len, int* bytes_written);

X509* RequestToCertificate(X509_REQ* req, EVP_PKEY* ca_key);

void RequestCaSignatureClient(SSL* ssl, void* data);

void PrintTime(const char* label);

int RsaPrime(BIGNUM *delta, const BIGNUM* start, BN_CTX* ctx);

#endif
