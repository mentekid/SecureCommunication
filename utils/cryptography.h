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

RSA *readPrivateKey(const char *);
RSA *readPublicKey(const char *);
int encryptRSA(unsigned char *, char *, RSA *);
int decryptRSA(unsigned char *, int, unsigned char *, RSA *);


int SignData(RSA *, unsigned char *, unsigned char *);
int VerifyData(const char *, const unsigned char *, unsigned char *, int);

int encryptAES(unsigned char *, unsigned char *, unsigned char *);
int decryptAES(unsigned char *, unsigned char *, unsigned char *);
unsigned char * generateAESkey(int);

#endif
