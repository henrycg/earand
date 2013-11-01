/* ssl_server.c
 *
 * Copyright (c) 2000 Sean Walton and Macmillan Publishers.  Use may be in
 * whole or in part in accordance to the General Public License (GPL).
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
*/

/*****************************************************************************/
/*** ssl_server.c                                                          ***/
/***                                                                       ***/
/*** Demonstrate an SSL server.                                            ***/
/*****************************************************************************/

#include <errno.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "ssl_server.h"

/*---------------------------------------------------------------------*/
/*--- OpenListener - create server socket                           ---*/
/*---------------------------------------------------------------------*/

int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;

    CHECK_CALL(sd = socket(PF_INET, SOCK_STREAM, 0));
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     ---*/
/*---------------------------------------------------------------------*/

SSL_CTX* InitServerCTX(void) {
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();		
    SSL_library_init();		

    SSL_load_error_strings();			
    ctx = SSL_CTX_new(SSLv23_server_method());
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile)
{
	  /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out certificates.                           ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* Get certificates (if available) */ 
    if ( cert != NULL ) { 
      printf("Server certificates:\n"); 
      line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0); 
      printf("Subject: %s\n", line); 
      free(line); 
      line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0); 
      printf("Issuer: %s\n", line);
      free(line);
      X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

void DebugServer(SSL* ssl, void* data) {
  char buf[1024];
  char reply[1024];
  int bytes;
  const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

  ShowCerts(ssl);								/* get any certificates */
  bytes = SSL_read(ssl, buf, sizeof(buf));	/* get request */
  if ( bytes > 0 )
  {
    buf[bytes] = 0;
    printf("Client msg: \"%s\"\n", buf);
    sprintf(reply, HTMLecho, buf);			/* construct reply */
    SSL_write(ssl, reply, strlen(reply));	/* send reply */
  }
  else
    ERR_print_errors_fp(stderr);
}

/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared)                ---*/
/*---------------------------------------------------------------------*/
void Servlet(SSL* ssl, ServerFunction server_func, void* server_data)	
{   
    if ( SSL_accept(ssl) == FAIL )					/* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        server_func(ssl, server_data); }
    int sd = SSL_get_fd(ssl);							/* get socket connection */
    SSL_free(ssl);									/* release SSL state */
    close(sd);										/* close connection */
}


/*---------------------------------------------------------------------*/
/*--- StartServer- create SSL socket server.                        ---*/
/*---------------------------------------------------------------------*/
int StartSSLServer(const char* cert_file, const char* key_file, int portnum, 
    ServerFunction server_func, void* server_data)
{   
    SSL_CTX* ctx = InitServerCTX();
    CHECK_CALL(ctx);

    LoadCertificates(ctx, cert_file, key_file);
    int server = OpenListener(portnum);

    while (1)
    {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);

        int client = accept(server, (struct sockaddr*)&addr, &len);		/* accept connection as usual */
        printf("Connection: %s:%d\n",
        	inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        SSL* ssl = SSL_new(ctx);
        CHECK_CALL(ssl);

        SSL_set_fd(ssl, client);
        Servlet(ssl, server_func, server_data);
    }

    close(server);
    SSL_CTX_free(ctx);
}

