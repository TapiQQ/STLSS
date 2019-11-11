all: server client client2

server: server.c
	gcc server.c -o server -L/usr/local/ssl/lib -lssl -lcrypto

client: client.c
	gcc client.c -o client -L/usr/local/ssl/lib -lssl -lcrypto
	
client: client2.c
	gcc client2.c -o client2 -L/usr/local/ssl/lib -lssl -lcrypto
