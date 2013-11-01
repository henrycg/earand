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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <sys/resource.h>
#include "bn_prime.h"
#include "util.h"

//--------------------------------------------------------------------------
// malloc memory and abort on failure
//--------------------------------------------------------------------------
void* safe_malloc( size_t size )
{
  void* ret = malloc( size );
  if ( ret == NULL ) fatal( "safe_malloc: Out of memory" );
  return ret;
}

//--------------------------------------------------------------------------
// realloc memory and abort on failure
//--------------------------------------------------------------------------
void* safe_realloc( void *ptr, size_t size )
{
  void* ret = realloc( ptr, size );
  if ( ret == NULL ) fatal( "safe_realloc: Out of memory" );
  return ret;
}

// ----------------------------------------------------------------------------
// report and exit gracefully from fatal error
// [This is a reimplementation and slight modification of a similar
// function by Alice Fischer, David W. Egger, and Stephen M. Ross that
// accompanied "Applied C: An Introduction and More", McGraw-Hill,
// 2001.]
// ----------------------------------------------------------------------------
void fatal( const char* format, ... )  // dots mean variable # args
{
  va_list ap;			// argument pointer

  va_start( ap, format );	  // get varying part of arg list
  vfprintf( stderr, format, ap ); // variable part as if a call to fprintf()
  va_end( ap );
  fprintf( stderr, "\n" );      // print a newline, just in case
  exit( EXIT_FAILURE );         // report failure to invoking process
}

int ReadOneBignum(BIGNUM **bn, FILE* file, const char *tag) {
  // BIGNUMs stored one line per file with format:
  //   bignum_name:hex_representation\n

  // Read the tag identifying the data item
  for(const char *p = tag; *p; p++) {
    int c = getc(file);
    if(c < 0) {
      return false;
    }
      
    if(c != *p) return false;
  }

  // First char after tag is ':'
  if(getc(file) != ':') return false;

  const int buflen = 65535;
  char buf[buflen+1];

  int ch, read = 0;
  while((ch = getc(file)) > 0 && read < buflen) {
    if(ch == '\n') {
      buf[read] = '\0';
      break;
    }
    buf[read] = ch;
    read++;
  }

  return BN_hex2bn(bn, buf);
}

int ReadOnePoint(EC_POINT **ec, EC_GROUP* g, FILE* file, const char *tag, BN_CTX* ctx) {
  // BIGNUMs stored one line per file with format:
  //   bignum_name:hex_representation\n

  // Read the tag identifying the data item
  for(const char *p = tag; *p; p++) {
    int c = getc(file);
    if(c < 0) {
      return false;
    }
      
    if(c != *p) return false;
  }

  // First char after tag is ':'
  if(getc(file) != ':') return false;

  const int buflen = 65535;
  char buf[buflen+1];

  int ch, read = 0;
  while((ch = getc(file)) > 0 && read < buflen) {
    if(ch == '\n') {
      buf[read] = '\0';
      break;
    }
    buf[read] = ch;
    read++;
  }

  return (EC_POINT_hex2point(g, buf, *ec, ctx) != NULL);
}

int WriteOneBignum(const char *tag, int tag_len, FILE* file, const BIGNUM* bn)
{
  if(fprintf(file, "%s", tag) != (tag_len-1)) return false;
  if(!putc(':', file)) return false;
  if(!BN_print_fp(file, bn)) return false;
  if(!putc('\n', file)) return false;

  return true;
}

int WriteOnePoint(const char *tag, int tag_len, FILE* file, 
    const EC_GROUP* g, const EC_POINT* ec, BN_CTX *ctx)
{
  if(fprintf(file, "%s", tag) != (tag_len-1)) return false;
  if(!putc(':', file)) return false;

  char* hex = EC_POINT_point2hex(g, ec, POINT_CONVERSION_UNCOMPRESSED, ctx);
  CHECK_CALL(hex);
  if(!fprintf(file, "%s", hex)) return false;
  if(!putc('\n', file)) return false;

  return true;
}

void SetupFileDescriptors(SSL* ssl, int* rfd, FILE** rfp,
    int* wfd, FILE** wfp)
{
  //int flags, result;
  // file descriptor for reading
  *rfd = SSL_get_rfd(ssl);
  //flags = fcntl(*rfd, F_GETFL);
  //result = fcntl(*rfd, F_SETFL, flags & ~O_NONBLOCK);
  *rfp = fdopen(dup(*rfd), "r");

  // file descriptor for writing
  *wfd = SSL_get_wfd(ssl);
//  flags = fcntl(*wfd, F_GETFL);
 // result = fcntl(*wfd, F_SETFL, flags & ~O_NONBLOCK);
  *wfp = fdopen(dup(*wfd), "w");
}

unsigned char* ToBase64(const unsigned char* msg, int msg_len, int* bytes_written)
{
  // Encode the sig in base64
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* bio = BIO_new(BIO_s_mem());
  CHECK_CALL(b64);
  CHECK_CALL(bio);

  CHECK_CALL(bio = BIO_push(b64, bio));
  CHECK_CALL(BIO_write(bio, msg, msg_len));
  CHECK_CALL(BIO_flush(bio));

  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);

  *bytes_written = mem->length;
  unsigned char* out = safe_malloc(sizeof(unsigned char) * mem->length);
  CHECK_CALL(strncpy((char*)out, (char*)mem->data, mem->length));
  CHECK_CALL(BIO_set_close(bio, BIO_CLOSE));

  BIO_free_all(bio);
  return out;
}

X509* RequestToCertificate(X509_REQ* req, EVP_PKEY* ca_key)
{
  // Create a new X509 cert
  X509* cert = X509_new();
  CHECK_CALL(cert);

  // Set the X509 version to 3
  CHECK_CALL(cert->cert_info->version = M_ASN1_INTEGER_new());
  CHECK_CALL(ASN1_INTEGER_set(cert->cert_info->version, 3));

  // Set the issuer field of the cert
  X509_NAME* issuer = X509_get_issuer_name(cert);
  CHECK_CALL(issuer);
  CHECK_CALL(X509_NAME_add_entry_by_txt(issuer, "O", MBSTRING_ASC, 
        (const unsigned char *)"CA Issuer", -1, -1, 0)); 
  CHECK_CALL(X509_set_issuer_name(cert, issuer));

  // Set the subject field of the cert
  X509_NAME* subj = X509_REQ_get_subject_name(req);
  CHECK_CALL(subj);
  CHECK_CALL(X509_set_subject_name(cert, subj));

  // Set cert to expire in one year
  CHECK_CALL(X509_gmtime_adj(cert->cert_info->validity->notBefore, 0));
  CHECK_CALL(X509_gmtime_adj(cert->cert_info->validity->notAfter, 365*24*60*60));

  // Set the cert public key
  CHECK_CALL(X509_set_pubkey(cert, X509_REQ_get_pubkey(req)));

  // Sign cert with CA private key
  CHECK_CALL(X509_sign(cert, ca_key, EVP_sha1()));

  return cert;
}

void RequestCaSignatureClient(SSL* ssl, void* data)
{
  int rfd, wfd;
  FILE* rfp;
  FILE* wfp;
  SetupFileDescriptors(ssl, &rfd, &rfp, &wfd, &wfp);

  struct ca_request_data* rr = (struct ca_request_data*)data;

  printf("writing...\n");
  CHECK_CALL(fprintf(wfp, "%d\n", rr->client_type));
  CHECK_CALL(!fflush(wfp));

  // Write X509 request
  if(!i2d_X509_fp(wfp, rr->cert)) {
    fatal("Could not write X509 cert");
  }
  CHECK_CALL(!fflush(wfp));

  printf("reading...\n");
  if(!(rr->cert = d2i_X509_fp(rfp, NULL))) {
    fatal("Could not read X509 response");
  }

  fclose(rfp);
  fclose(wfp);
}

void PrintTime(const char* label)
{
  struct timeval tv;
  struct rusage ru;
  CHECK_CALL(!gettimeofday(&tv, NULL));
  CHECK_CALL(!getrusage(RUSAGE_SELF, &ru));

  fprintf(stderr, "%s | %lld.%lld | %lld.%lld\n", label, 
      (long long)tv.tv_sec, (long long)tv.tv_usec, 
      (long long)ru.ru_utime.tv_sec, (long long)ru.ru_utime.tv_usec);
}

/** 
 * This function is adapted from the OpenSSL source 
 * (so don't blame me for the goto statements!)
 *
 * Input is an ODD number start. Output is a delta
 * value such that (start+delta_out) is prime.
 */
int RsaPrime(BIGNUM *delta_out, const BIGNUM* start, BN_CTX* ctx)
{
  if(!BN_is_odd(start)) 
    fatal("Input to ProbablePrime must be odd");
 
  int i;
  prime_t mods[NUMPRIMES];
  BN_ULONG delta,maxdelta;

  BIGNUM* rnd = BN_dup(start);
  CHECK_CALL(rnd);
  /* we now have a random number 'rand' to test. */
  for (i=1; i<NUMPRIMES; i++)
    mods[i]=(prime_t)BN_mod_word(rnd,(BN_ULONG)primes[i]);
  maxdelta=BN_MASK2 - primes[NUMPRIMES-1];
  delta=0;
loop: 
  for (i=1; i<NUMPRIMES; i++) {
    /* check that rnd is not a prime and also
    * that gcd(rnd-1,primes) == 1 (except for 2) */
    if (((mods[i]+delta)%primes[i]) <= 1) {
      delta+=2;
      if (delta > maxdelta) return 0;
      goto loop;
    }
  }

  BIGNUM *tmp = BN_dup(start);
  CHECK_CALL(tmp);

  if(!BN_add_word(tmp, delta)) return false;

  // Make sure it's prime
  if(!BN_is_prime_fasttest(tmp, BN_prime_checks, NULL, NULL, ctx, 0)) {
    delta += 2;
    BN_free(tmp);
    goto loop;
  }

  BIGNUM *e = BN_new();
  CHECK_CALL(e);
  CHECK_CALL(BN_set_word(e, RsaEncryptionExponent));
  if (!BN_sub(tmp, tmp, BN_value_one())) return false;
  if (!BN_gcd(tmp, tmp, e, ctx)) return false;
  if (!BN_is_one(tmp)) {
    delta += 2;
    BN_free(tmp);
    goto loop;
  }

  BN_free(e);

  BN_free(tmp);
  BN_free(rnd);

  if (!BN_set_word(delta_out, delta)) return false;

  return(1);
}

