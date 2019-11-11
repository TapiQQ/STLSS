#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define RETURN_NULL(x) if ((x)==NULL) exit (1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }


int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

	memset (&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("10.0.1.1");

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }
	
	s = connect(s, (struct sockaddr*) &addr, sizeof(addr));
	if (s < 0) {
	perror("Unable to connect socket");
	exit(EXIT_FAILURE);
    }
	
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
	char *str;
	int err;
	SSL *ssl;
	int sock;
    SSL_CTX *ctx;
	X509    *server_cert;
    char buf [4096];
	char 	hello[80];
	
	printf ("Message to be sent to the SSL server: ");
  	fgets (hello, 80, stdin);
	
	init_openssl();
	
	ctx = create_context();
	//configure_context(ctx);
	
	if (!SSL_CTX_load_verify_locations(ctx, "cert.crt", NULL)) {
       	        ERR_print_errors_fp(stderr);
       	        exit(1);
	}
	
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
 
    SSL_CTX_set_verify_depth(ctx,1);

    sock = create_socket(4433);
	printf("Socket Created on port 4433\n");

	ssl = SSL_new(ctx);
	RETURN_NULL(ssl);
	
	SSL_set_fd(ssl, sock);
	
	err = SSL_connect(ssl);
	RETURN_SSL(err);

	printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
	
	server_cert = SSL_get_peer_certificate(ssl);  
	
		if (server_cert != NULL)
        {
		printf ("Server certificate:\n");

		str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
		RETURN_NULL(str);
		printf ("\t subject: %s\n", str);
		free (str);
 
		str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
		RETURN_NULL(str);
		printf ("\t issuer: %s\n", str);
		free(str);
 
		X509_free (server_cert);

	}
        else
                printf("The SSL server does not have certificate.\n");
			
			
	err = SSL_write(ssl, hello, strlen(hello)); 
	RETURN_SSL(err);
	
	err = SSL_read(ssl, buf, sizeof(buf)-1);   
	RETURN_SSL(err);
  	buf[err] = '\0';
  	printf ("Received %d chars:'%s'\n", err, buf);
	
	err = SSL_shutdown(ssl);
	RETURN_SSL(err);
	
	err = close(sock);
	RETURN_SSL(err);
	
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	cleanup_openssl();
	
}
