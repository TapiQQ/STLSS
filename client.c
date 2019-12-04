#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define VERBOSE	1

static int ssl_session_ctx_id = 69;


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


	if (SSL_CTX_use_certificate_file(ctx, "cert.crt", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.key", SSL_FILETYPE_PEM) <= 0) {
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
		if(VERBOSE == 1){	printf("socket() returned: %d\n", sock);	}
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
        if(VERBOSE == 1){	printf("Socket close return value: %d\n", err);	}
	if(err < 0){
        	if ((err)==-1){
			perror("close");
			exit(1);
		}
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
	if(ctx == NULL){exit(1);}
	configure_context(ctx);
	if(ctx == NULL){exit(1);}

	ssl = SSL_new (ctx);
	if(ctx == NULL){exit(1);}

	err = SSL_set_fd(ssl, sock);


	//Set session if not NULL
	if(session != NULL){
		if(VERBOSE == 1){	printf("non-NULL session, setting session\n");	}
		err = SSL_set_session(ssl, session);
		SSL_SESSION_free(session);
		if(VERBOSE == 1){	printf("SSL_set_session return value: %d\n", err);	}
	}


	//Establish connection
	err = SSL_connect(ssl);
	if(VERBOSE == 1){	printf("SSL_connect return value: %d\n", err);	}



	/* Informational output (optional) */
  	printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

	server_cert = SSL_get_peer_certificate (ssl);   

	if (server_cert != NULL)
        {
		printf ("Server certificate:\n");

		str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
		if(ctx == NULL){exit(1);}
		printf ("\t subject: %s\n", str);
		free (str);

		str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
		if(ctx == NULL){exit(1);}
		printf ("\t issuer: %s\n", str);
		free(str);

		X509_free (server_cert);

	}
        else
            printf("The SSL server does not have certificate.\n");


	//Check session reuse
	if(SSL_session_reused(ssl) == 1){
		printf("Session Reused\n");
	}
	else{
		printf("New Session\n");
	}

	//Read and write operations
	err = SSL_write(ssl, msg, strlen(msg));
	if ((err)==-1){
		ERR_print_errors_fp(stderr);
		exit(1);
	}


	err = SSL_read(ssl, buf, sizeof(buf)-1);
	if ((err)==-1){
		ERR_print_errors_fp(stderr);
		exit(1);
	}

  	buf[err] = '\0';
  	printf ("Received %d chars:'%s'\n", err, buf);



        //SAVE SESSION
        session = SSL_get1_session(ssl);


	//Communicate connection shutdown
	err = SSL_shutdown(ssl);
	if(VERBOSE == 1){	printf("SSL_shutdown #1: %d\n", err);	}
	if(err == 0){
		//sleep(5);
		err = SSL_shutdown(ssl);
		if(VERBOSE == 1){	printf("SSL_shutdown #2: %d\n", err);	}
		if(err < 0){
			err = SSL_get_error(ssl, err);
			if(VERBOSE == 1){	printf("SSL_shutdown error code: %d\n", err);	}
		}
	}



        if(ctx == NULL){exit(1);}
        if(VERBOSE == 1){       printf("Session saved successfully\n"); }


        //Print SSL Session
        SSL_SESSION_print_fp(stdout, session);



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
	SSL_SESSION	**sess;
	char hello[80] = "ping";
	char addr[10];
	FILE	*sessionfile;
	time_t now = time(0);

	init_openssl();

	while(1){
	        printf ("IP address of the SSL server: ");
        	fgets (addr, 10, stdin);
	  	printf ("Message to be sent to the SSL server: ");
  		fgets (hello, 80, stdin);
		sock = create_socket(4433, addr);
		session = create_ssl_connection(sock, session, hello);
		close_socket(sock);

	}

	if(VERBOSE == 1){	printf("Success!\n");	}
}
