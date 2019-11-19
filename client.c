#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#ifdef __VMS
#include <socket.h>
#include <inet.h>
 
#include <in.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
 
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define RETURN_NULL(x) if ((x)==NULL) exit (1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }
 
static int verify_callback(int ok, X509_STORE_CTX *ctx);
 
#define RSA_CLIENT_CERT	"cert.crt"
#define RSA_CLIENT_KEY 	"key.key"
 
#define RSA_CLIENT_CA_CERT      "cert.crt"
#define RSA_CLIENT_CA_PATH      "sys$common:[syshlp.examples.ssl]"
 
#define ON      1
#define OFF     0

#define VERBOSE	0


void init_openssl()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
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
	if (SSL_CTX_use_certificate_file(ctx, RSA_CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, RSA_CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

}



int create_socket(int port, char* ip_addr)
{
	int sock;
	struct sockaddr_in addr;

	//Create socket
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0){
		if(VERBOSE == ON){	printf("socket() returned: %d\n", sock);	}
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}
	else{
		printf("Socket created in port: %d\n", port);
	}

	//Initialize address struct
	memset(&addr, '\0', sizeof(addr));
	addr.sin_family	= AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip_addr);

	//connect socket
	if(connect(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0){
		perror("Unable to connect");
		exit(EXIT_FAILURE);
	}

	return sock;
}

int close_socket(int sock){
	int err;

	err = close(sock);
        if(VERBOSE == ON){	printf("Socket close return value: %d\n", err);	}
	if(err < 0){
        	RETURN_ERR(err, "close");
	}

	return 0;
}


SSL_SESSION *create_ssl_connection(int sock, SSL_SESSION *session, char *msg)
{
	int 	err;
	SSL	*ssl;
	SSL_CTX	*ctx;
	X509 	*server_cert;
	char 	*str;
	char  	buf [4096];


	ctx = create_context();
	RETURN_NULL(ctx);
	configure_context(ctx);
	RETURN_NULL(ctx);

	ssl = SSL_new (ctx);
	RETURN_NULL(ssl);

	err = SSL_set_fd(ssl, sock);


	//Set session if not NULL
	if(session != NULL){
		printf("non-NULL session, setting session\n");
		err = SSL_set_session(ssl, session);
		printf("SSL_set_session return value: %d\n", err);
	}


	//Establish connection
	err = SSL_connect(ssl);
	if(VERBOSE == ON){	printf("SSL_connect return value: %d\n", err);	}


	printf("Session Reuse: %d\n", SSL_session_reused(ssl));

	/* Informational output (optional) */
  	printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

	server_cert = SSL_get_peer_certificate (ssl);   

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


	//Read and write operations
	err = SSL_write(ssl, msg, strlen(msg)); 
	RETURN_SSL(err);

	err = SSL_read(ssl, buf, sizeof(buf)-1);
	RETURN_SSL(err);
  	buf[err] = '\0';
  	printf ("Received %d chars:'%s'\n", err, buf);


	//SAVE SESSION
	session = SSL_get1_session(ssl);
	RETURN_NULL(session);
	printf("Session saved successfully\n");


	//Communicate connection shutdown
	err = SSL_shutdown(ssl);
	if(VERBOSE == ON){	printf("SSL_shutdown #1: %d\n", err);	}
	if(err == 0){
		//sleep(5);
		err = SSL_shutdown(ssl);
		if(VERBOSE == ON){	printf("SSL_shutdown #2: %d\n", err);	}
		if(err < 0){
			err = SSL_get_error(ssl, err);
			if(VERBOSE == ON){	printf("SSL_shutdown error code: %d\n", err);	}
		}
	}

	SSL_CTX_free(ctx);
	SSL_free(ssl);


	//returns pointer to the ssl session
	return session;
}


void main()
{
  	int 	err;
  	int 	sock;
	SSL_SESSION	*session = NULL;
	char hello1[80] = "kek";
	char hello2[80] = "bur";


	init_openssl();

	sock = create_socket(4433, "10.0.1.1");
	session = create_ssl_connection(sock, session, hello1);
	close_socket(sock);

	//printf("%d", session->version);

	sock = create_socket(4433, "10.0.1.1");
	session = create_ssl_connection(sock, session, hello2);
	close_socket(sock);


	if(VERBOSE == ON){	printf("Success!\n");	}
}
