#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

	memset (&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl("10.0.1.1");

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }
	
	CHK_ERR(s, "socket");
	
	err = connect(s, (struct sockaddr*) &addr, sizeof(addr));
	CHK_ERR(err, "connect");
	

    return s;
}

void init_openssl()
{ 
	SSL_library_init();
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
	
	int sock;
    SSL_CTX *ctx;
    char buf [4096];
	char 	hello[80];
	
	printf ("Message to be sent to the SSL server: ");
  	fgets (hello, 80, stdin);
	
	init_openssl();
	
	ctx = create_context();
	configure_context(ctx);
	
	if (!SSL_CTX_load_verify_locations(ctx, "cert.crt", NULL)) {
       	        ERR_print_errors_fp(stderr);
       	        exit(1);
	}
	
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
 
    SSL_CTX_set_verify_depth(ctx,1);

    sock = create_socket(4433);
	printf("Socket Created on port 4433\n");
	

}