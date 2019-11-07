server: server.c
	gcc server.c -o server -L/usr/local/ssl/lib -lssl -lcrypto
