/** \file cryptography.h
 * Function declarations for the cryptography.c file
 * Author: Yannis Mentekidis
 * Date: December 2015 - January 2016
 */

#ifndef CRYPTOGRAPHY_GUARD
#define CRYPTOGRAPHY_GUARD 0

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

RSA *readPrivateKey(char *);
RSA *readPublicKey(char *);
int encryptRSA(char *, char *, RSA *);
int decryptRSA(unsigned char *, int, char *, RSA *);

int encryptAES(char *, char *, unsigned char *);
int decryptAES(char *, char *, unsigned char *);
unsigned char * generateAESkey(int);

#endif
