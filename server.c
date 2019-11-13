#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define ON	1
#define OFF	0

#define VERBOSE	0

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    memset(&addr, 0 , sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 5) < 0) {
	perror("Unable to listen");
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

    method = SSLv23_server_method();

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
    int err;
    int sock;
    SSL_CTX *ctx;
    char buf [4096];

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);
    printf("Server started on port 4433\n");

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
	printf("Connection from %x, port %x\n", addr.sin_addr.s_addr, addr.sin_port);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
	    SSL_read(ssl,buf, sizeof(buf)-1);
	    printf("Received message: '%s'\n", buf);
            SSL_write(ssl, reply, strlen(reply));
        }

	err = SSL_shutdown(ssl);
        if(VERBOSE == ON){	printf("SSL_shutdown #1: %d\n", err);	}
	if(err == 0){
		//sleep(5);
		err = SSL_shutdown(ssl);
	        if(VERBOSE == ON){	printf("SSL_shutdown #2: %d\n", err);	}
		if(err <= 0){
			err = SSL_get_error(ssl,err);
			if(VERBOSE == ON){	printf("SSL_shutdown error code: %d\n", err);	}
		}
	}

        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
