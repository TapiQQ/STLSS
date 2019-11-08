all: server client

server: server.c
	gcc server.c -o server -L/usr/local/ssl/lib -lssl -lcrypto

client: client.c
	gcc client.c -o client -L/usr/local/ssl/lib -lssl -lcrypto
