
all: cryptography.o client.c
	gcc -Wall -o client client.c cryptography.o -lcrypto

cryptography.o: ../utils/cryptography.c ../utils/cryptography.h
	gcc -c ../utils/cryptography.c 

clean:
	rm cryptography.o client
