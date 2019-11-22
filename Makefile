all: server client

server: server.c
	gcc server.c cache.c -o server -L/usr/local/ssl/lib -lssl -lcrypto -lgdbm

client: client.c
	gcc client.c -o client -L/usr/local/ssl/lib -lssl -lcrypto
