/** \file client.c
 * Implements a chat client. The client connects to a
 * server listening port and transmits/receives messages.
 * Communication is implemented via the socket api
 * Security is implemented via the openssl api
 *
 * Author: Yannis Mentekidis
 * Date: December 2015 - January 2016
*/

#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include "../utils/cryptography.h"


/**
 * Constants
 */
#define MAX_MSG_SZ 2000 //max message size

#define PORT 8888 //port to connect to
static const char SERVER[] = "127.0.0.1"; //IP to connect to

static const char server_key[] = "server_cert.pem"; //server certificate file
static const char client_private_key[] = "client_pkey.pem"; //client private key
static const char client_cert[] = "client_cert.pem"; //client certificate file

/**
 * Functions
 */
int connectToServer(void);
unsigned char *getSessionKey(int);
void clientLoop(int, unsigned char *);


/** \brief Connects to SERVER and communicates via encrypted channel
 *
 * Exchanges an AES encryption key encrypted with RSA, then initiates
 * encrypted communication with SERVER
 */
int main(int argc , char *argv[])
{

    /* connect to remote server */
    int sock = connectToServer();

    /* exchange encryption keys */
    unsigned char *session_key = getSessionKey(sock);

    /* client-server communication */
    clientLoop(sock, session_key);

    close(sock); //unnecessary
    return 0;
}

/** \brief Server connection procedure
 * Connects a socket to a remote server and
 * returns the socket to the caller
 */
int connectToServer(){
    int sock;
    struct sockaddr_in server;

    /* create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1){
        perror("Attempt to create socket");
        exit(1);
    }
    printf("Socket created\n");

    /* connect to server */
    server.sin_addr.s_addr = inet_addr(SERVER);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    if (
            connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0){
        perror("Attempting to connect");
        exit(1); //fatal
    }

    printf("Connected to %s\n", SERVER);
    return sock;
}

/** \brief Exchanges a Session Key through the socket
 * Protocol: The client will generate a 32 bit AES key which
 * it encrypts using the server's public key. After that,
 * all communication happens via AES - encrypted channel.
 */
unsigned char *getSessionKey(int sock){
    srand(time(NULL));
    unsigned char *session_key = generateAESkey(32);

    printf("Session key:\n");
    int i;
    for (i = 0; i < 32; i++){
        printf("0x%02x ", session_key[i]);
        if (i%8==7) printf("\n");
    }

    //encrypt key with server's public RSA key
    RSA *serverPubKey = readPublicKey(server_key);
    char *encrypted_session_key = (char *) malloc(MAX_MSG_SZ*sizeof(char));
    int keylen = encryptRSA(session_key, encrypted_session_key, serverPubKey);

    //send session key to server
    if (send(sock, encrypted_session_key, keylen, 0) < 0){
        perror("Send failed");
        exit(1);
    }
    free(encrypted_session_key); //not needed any more
    return session_key;
}

/** \brief client-side communication procedure
 * Reads data from stdin, encrypts it with the
 * session_key and sends it through sock to a remote
 * server. Reads encrypted replies and decrypts them
 * with the same key.
 */
void clientLoop(int sock, unsigned char *session_key){

    char message[MAX_MSG_SZ];
    unsigned char server_reply[MAX_MSG_SZ], crypt_msg[MAX_MSG_SZ], crypt_reply[MAX_MSG_SZ];

    while(1)
    {
        /* zero out buffers */
        memset(message, 0, MAX_MSG_SZ);
        memset(server_reply, 0, MAX_MSG_SZ);
        memset(crypt_msg, 0, MAX_MSG_SZ);
        memset(crypt_reply, 0, MAX_MSG_SZ);

        /* read message to be sent */
        printf("Enter message: ");
        fgets(message, MAX_MSG_SZ, stdin);

        /* encryption */
        int len = encryptAES((unsigned char *) message, crypt_msg, session_key);

        /* send data */
        if( send(sock , crypt_msg , len , 0) < 0){
            perror("Send failed");
            exit(1);
        }

        /* sign (encrypted!) data and send signature as well */
        RSA *privateKey = readPrivateKey(client_private_key);
        unsigned char *sig = (unsigned char *) malloc(2048 * sizeof(char));
        int siglen = SignData(privateKey, crypt_msg, sig);
        if ( send(sock, sig, siglen, 0) < 0){
            perror("Send failed");
            exit(1);
        }

        /* receive a reply */
        if( recv(sock , crypt_reply , MAX_MSG_SZ , 0) < 0){
            perror("receive failed");
            exit(1);
        }

        /* decryption */
        decryptAES(crypt_reply, server_reply, session_key);

        /* display reply */
        printf("Server reply: %s\n", server_reply);
    }
}
