/**\file server.c
 * C socket server example implementing secure communications
 * via the openssl api and the socket api
 * Author: Yannis Mentekidis
 * Date: December 2015 - January 2016
*/
#include<stdio.h>
#include<string.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write
#include <stdlib.h>
#include "../utils/cryptography.h"
 

/**
 * constants
 */
#define MAX_MSG_SZ 2000
#define PORT 8888
#define KEYLEN 32
static const char server_key[] = "server_pkey.pem"; //server private key
static const char client_cert[] = "client_cert.pem"; //client public key

/**
 * functions
 */
int openConnection(void);
unsigned char *getSessionKey(int);
void serverLoop(int, unsigned char *);

/**
 * Opens a connection, exchanges a session key and
 * communicates with symmetric encryption using the
 * session key
 */
int main(int argc , char *argv[]){

    /* Wait for a connection */
    int client_sock = openConnection();

    /* exchange encryption keys */
    unsigned char *session_key = getSessionKey(client_sock);

    /* client-server communication */
    serverLoop(client_sock, session_key);
    
    return 0;
}

/** \brief Creates a socket and waits for a connection
 * Creates a socket and binds on PORT. Then, waits for
 * incoming connections and accepts the first incoming
 * connection.
 * Returns the socket after a succesful connection
 */
int openConnection(void){
    int socket_desc , client_sock , c ;
    struct sockaddr_in server , client;
     
    /* create socket */
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( PORT );
     
    /* bind socket to port */
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

     
    /* wait for incoming connection */
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
    //start listening
    listen(socket_desc , 3);
     
    /* accept connection from an incoming client */
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
    {
        perror("accept failed");
        exit(1);
    }
    puts("Connection accepted");

    return client_sock;
}

/* \brief receives a session key from the client
 * Protocol: Client generates an AES key which is sent
 * encrypted by RSA. Use the private key to decrypt the
 * AES key and use the AES key for the rest of the session
 */
unsigned char *getSessionKey(int client_sock){
    unsigned char client_message[MAX_MSG_SZ];
    int read_size;
    
    // get encrypted AES key from client
    if ( (read_size = recv(client_sock, client_message, MAX_MSG_SZ, 0)) < 0){
        perror("receive failed");
        exit(1);
    }

    // decrypt AES key using server private key
    RSA * privateKey;
    privateKey = readPrivateKey(server_key);
    if (privateKey == NULL){
        //key file not found
        exit(1); //fatal
    }
    unsigned char *session_key;
    session_key = (unsigned char *) malloc(KEYLEN*sizeof(char));
    int keylen = 
        decryptRSA(
                client_message,
                read_size,
                session_key,
                privateKey
        );

    printf("Session key:\n");
    int i;
    for (i = 0; i < keylen; i++){
        printf("0x%02x ", session_key[i]);
        if (i%8==7) printf("\n");
    }
    memset(client_message, 0, MAX_MSG_SZ); //zero out buffer
    return session_key;
}

/** \brief implements the server side of the communication loop
 * The server waits for encrypted data, which is decrypted and
 * displayed on screen. Then, the server's user inputs a response
 * to the client's message, which is again encrypted and sent
 * back to the client
 */
void serverLoop(int client_sock, unsigned char *session_key){
    unsigned char client_message[MAX_MSG_SZ];
    unsigned char crypt_msg[MAX_MSG_SZ];
    unsigned char signature[2048];
    int read_size;

     
    /* client-server communication */
    while( (read_size = recv(client_sock , crypt_msg , MAX_MSG_SZ , 0)) > 0 )
    {
        /* receive signature of data */
        int siglen = recv(client_sock, signature, 2048, 0);
        int verified = VerifyData(client_cert, crypt_msg, signature, siglen);
        
        /* decrypt data */
        decryptAES(crypt_msg, client_message, session_key);

        /* print the received message */
        printf("Client message[%s]: %s\n", verified?"verified":"not verified", client_message);
        
        /* send a response back */
        char response[MAX_MSG_SZ];
        unsigned char crypt_reply[MAX_MSG_SZ];
        printf("Your response: ");
        fgets(response, MAX_MSG_SZ, stdin); //secure string input
        int len = encryptAES((unsigned char *) response, crypt_reply, session_key);
        write(client_sock , crypt_reply , len);

        
        /* zero out buffers */
        memset(client_message, 0, MAX_MSG_SZ);
        memset(crypt_msg, 0, MAX_MSG_SZ);
        memset(response, 0, MAX_MSG_SZ);
        memset(crypt_reply, 0, MAX_MSG_SZ);
        memset(signature, 0, 2048);
    }
     
    if(read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }
     
    return;

}

