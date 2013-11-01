/* ssl_client.c
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
/*** ssl_client.c                                                          ***/
/***                                                                       ***/
/*** Demonstrate an SSL client.                                            ***/
/*****************************************************************************/

#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssl_client.h"
#include "util.h"

#define FAIL    -1

/*---------------------------------------------------------------------*/
/*--- OpenConnection - create socket and connect to server.         ---*/
/*---------------------------------------------------------------------*/
int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        return -1;
    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitCTX(void) {
    OpenSSL_add_all_algorithms();
    SSL_library_init();		
    SSL_load_error_strings();

    /** 
     * For some reason, SSL_METHOD is const
     * on Debian but not on Mac OS X
     */
#ifdef __APPLE__
    SSL_METHOD* method = SSLv23_client_method();
#else
    const SSL_METHOD* method = SSLv23_client_method();
#endif
    SSL_CTX* ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL context and connect                         ---*/
/*---------------------------------------------------------------------*/
bool MakeSSLRequest(const char* hostname, int port, 
    ClientFunction client_func, void* client_data)
{   
    // Set up context
    SSL_CTX* ctx = InitCTX();
    CHECK_CALL(ctx);

    // Connect to server
    int server = OpenConnection(hostname, port);
    if(server < 0) return false;
    CHECK_CALL(server);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    // Do handshake
    if ( SSL_connect(ssl) == FAIL ) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    client_func(ssl, client_data);

    fprintf(stderr, "Connected with %s encryption\n", SSL_get_cipher(ssl));

    SSL_free(ssl);
    
    close(server);

    SSL_CTX_free(ctx);
    ERR_free_strings();
    EVP_cleanup();

    return true;
}

