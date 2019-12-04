#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "cache.h"

#define ON	1
#define OFF	0

#define VERBOSE	0

static int ssl_session_ctx_id = 69;


//new session callback function
static int new_session_cb(struct ssl_st *ssl, SSL_SESSION *session)
{
	int r;

	if(VERBOSE == 1){	printf("!!! NEW SESSION CB !!!\n");	}

        unsigned int var = 32;

        unsigned int *max_session_id_length = &var;


	//printf("%x\n", SSL_SESSION_get_id(session, max_session_id_length));


	// store the session
	r = ssl_scache_store(session,10000);

	if(r == 1 && VERBOSE == 1){
		printf("New session successfully stored\n");
	}


	return 0;
}

static void remove_session_cb(struct ssl_ctx_st *ctx, SSL_SESSION *sess)
{
    if(VERBOSE == 1){	printf("!!! REMOVE SESSION CB !!!\n");	}
    return;
}

static SSL_SESSION *get_session_cb(struct ssl_st *ssl, const unsigned char *data, int len, int *copy)
{
    if(VERBOSE == 1){	printf("!!! GET SESSION CB !!!\n");	}

    SSL_SESSION *session;

    session = ssl_scache_retrieve((unsigned char *)data, len);

    if(session != NULL){
	if(VERBOSE == 1){	printf("ssl_scache_retrieve successful!\n");	}
    }
    else{
	printf("ssl_scache_retrieve returned NULL!\n");
    }

    *copy = 0;

    return session;
}

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
    //SSL_CTX_set_ecdh_auto(ctx, 1);

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR | SSL_SESS_CACHE_NO_INTERNAL);

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_TICKET);

    SSL_CTX_set_session_id_context(ctx, (void *)&ssl_session_ctx_id, sizeof(ssl_session_ctx_id));

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }


    SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
    SSL_CTX_sess_set_remove_cb(ctx, remove_session_cb);
    SSL_CTX_sess_set_get_cb(ctx, get_session_cb);


}

void print_session_statistics(SSL_CTX *ctx)
{
        printf("Number of sessions in the internal session cache: %ld\n", SSL_CTX_sess_number(ctx));
        printf("Number of started handhakes in client mode: %ld\n", SSL_CTX_sess_connect(ctx));
        printf("Number of established sessions in client mode: %ld\n", SSL_CTX_sess_connect_good(ctx));
        printf("Number of started renegotiations in client mode: %ld\n", SSL_CTX_sess_connect_renegotiate(ctx));
        printf("Number of started SSL/TLS handshakes in server mode:%ld\n", SSL_CTX_sess_accept(ctx));
        printf("Number of successfully established SSL/TLS sessions in server mode: %ld\n", SSL_CTX_sess_accept_good(ctx));
        printf("Number of started renegotiations in server mode: %ld\n", SSL_CTX_sess_accept_renegotiate(ctx));
        printf("Number of successfully reused sessions: %ld\n", SSL_CTX_sess_hits(ctx));
        printf("Number of successfully retrieved sessions from the external session cache in server mode: %ld\n", SSL_CTX_sess_cb_hits(ctx));
        printf("Number of sessions proposed by clients that were not found in the internal session cache in server mode: %ld\n", SSL_CTX_sess_misses(ctx));
        printf("Number of sessions proposed by clients and either found in the internal or external session cache in server mode, but that were invalid due to timeout:%ld\n", SSL_CTX_sess_timeouts(ctx));
        printf("Number of sessions that were removed because the maximum session cache size was exceeded: %ld\n", SSL_CTX_sess_cache_full(ctx));
}

int main(int argc, char **argv)
{
    int err;
    int sock;
    SSL_CTX *ctx;
    SSL_SESSION	*session = NULL;
    SSL_SESSION **sess;
    char buf [4096];
    unsigned char *pp = NULL;
    int asn1_size;
    FILE *sessionfile;
    time_t now = time(0);
    const unsigned char **sessid = malloc(sizeof(const unsigned char**));

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    //print_session_statistics(ctx);

    sock = create_socket(4433);
    printf("Server started on port 4433\n");

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "pong";


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


        //Check session reuse
        if(SSL_session_reused(ssl) == 1){
                printf("Session Reused\n");
        }
        else{
                printf("New Session\n");
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

	print_session_statistics(ctx);

	SSL_SESSION_print_fp(stdout, SSL_get1_session(ssl));

        SSL_free(ssl);
        close(client);
    }




    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
