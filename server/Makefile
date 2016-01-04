all: cryptography.o server.c
	gcc -Wall -o server server.c cryptography.o -lcrypto

cryptography.o: ../utils/cryptography.c ../utils/cryptography.h
	gcc -c ../utils/cryptography.c

clean:
	rm cryptography.o server
