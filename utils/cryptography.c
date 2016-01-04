/** \file cryptography.c
 * Library implementing public/private key reads and encryption
 * using the openssl library. These functions are used here so that
 * other programs can transparently compile against them.
 * Author: Yannis Mentekidis
 * Date: December 2015 - January 2016
 */

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>


/** \brief Reads a Private Key
 * readPrivateKey reads an RSA Private Key from
 * a .pem file and returns it
 */
RSA *readPrivateKey(const char *privatefilename){
	RSA *private_key;
	FILE *fp;
	fp = fopen(privatefilename, "r");
    if (fp == NULL){
        perror("Attempt to read Private Key");
        return NULL;
    }
	private_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
    return private_key; 
}

/** \brief Reads a Public Key
 * readPublicKey reads an RSA Public Key from
 * a certificate file and returns it
 */
RSA *readPublicKey(const char *certfilename){
	
    /* Open cert file */
    FILE *fp2;
	fp2 = fopen(certfilename, "r");
    if (fp2 == NULL){ //protect from file not found
        perror("Attempt to open Certificate");
        return NULL;
    }

	/* read certificate into cert */
	X509 *cert;
	cert = PEM_read_X509(fp2, NULL, NULL, NULL);
	if(!cert){ //protect from mangled cert file
        perror("Attempt to read certificate");
		return NULL;
	}
	fclose(fp2);
	
    /* get public key from certificate */
	EVP_PKEY *public_key;
	public_key = X509_get_pubkey(cert);
    return EVP_PKEY_get1_RSA(public_key); //EVP_PKEY to RSA
}


/** \brief signs data with an RSA private key
 * Reads a private key from keyfile, signs data in the data
 * buffer and places the computed signature in the signature
 * buffer. Returns the length of the signature.
 * Uses the SHA1 digest algorithm for the signing.
 */
int SignData(RSA *key, unsigned char *data, unsigned char *signature){
    
    EVP_PKEY privateKey;
    EVP_PKEY_set1_RSA(&privateKey, key);

    /* Signing Context */
    EVP_MD_CTX ctx;
    EVP_SignInit(&ctx, EVP_sha1());

    /* Add data to Context */
    EVP_SignUpdate(&ctx, data, strlen(data));

    /* Store signature to sig_buf */
    int sig_len;
    int check = EVP_SignFinal(&ctx, signature, &sig_len, &privateKey);

    if(!check){
        perror("Attempting to Sign Data");
        return -1;
    }

    return sig_len;
}

/** \brief Verifies data has not been tampered with
 * Reads a public key from a certificate, and verifies that
 * the contents of the data buffer produce the signature in
 * the signature buffer when signed with an RSA/SHA1 context
 */
int VerifyData(char *certfilename, const unsigned char *data, unsigned char *signature, int sig_len){
    /* Read RSA key from certificate */
    FILE *fp;
	fp = fopen(certfilename, "r");
    if (fp == NULL){ //protect from file not found
        perror("Attempt to open Certificate");
        return -1;
    }

	X509 *cert;
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	if(!cert){ //protect from mangled cert file
        perror("Attempt to read certificate");
		return -1;
	}
	fclose(fp);
	
	EVP_PKEY *publicKey;
	publicKey = X509_get_pubkey(cert);

    /* Initialize context */
    EVP_MD_CTX ctx;
    EVP_VerifyInit(&ctx, EVP_sha1());

    /* Add data */
    EVP_VerifyUpdate(&ctx, data, strlen(data));

    return EVP_VerifyFinal(
            &ctx, signature, sig_len, publicKey);
}

/** \brief Encrypts message with public_key
 * encryptRSA creates a cryptogram from a message with
 * a public RSA key. The cryptogram can only be decrypted
 * using the matching private RSA key. This ensures that
 * only the intended recepient (whose public key was used
 * during encryption) will be able to decrypt the message
 */
int encryptRSA(unsigned char *message, char *crypt, RSA *public_key){

    int msg_len = strlen(message);

    /* encrypt with given public key */
    int cryptsize = 
        RSA_public_encrypt(
                msg_len, //flen bytes
                message, //from
                crypt,   //to
                public_key, //with key
                RSA_PKCS1_PADDING //padding info
        );

    return cryptsize;
}

/** \brief Decrypts crypto with private_key
 * decryptRSA creates a message from a cryptogram that was
 * encrypted with an RSA public key matching the known
 * private key. If the private key is secret, this ensures
 * only the owners will be able to decrypt the message correctly
 */
int decryptRSA(unsigned char *crypto, int crypt_len, unsigned char *message, RSA *private_key){

    int msg_len = 
        RSA_private_decrypt(
                crypt_len, //flen bytes
                crypto,    //from
                message,   //to
                private_key, //with key
                RSA_PKCS1_PADDING //padding info
        );

    return msg_len;
}

/** \brief Encrypts message with 128 bit key into crypto
 * Uses symmetric key cryptography (AES algorithm) to
 * encrypt a message. If the key used for the encryption
 * is only known between two associates, the message will
 * remain private.
 */
int encryptAES(unsigned char *message, unsigned char *crypto, unsigned char *key){
    /* Create Key */
    AES_KEY encrypt_key;
    AES_set_encrypt_key(key, 128, &encrypt_key);

    /* Encrypt message with Key */
    AES_encrypt(message, crypto, &encrypt_key);

    int i, len=0;
    for (i=0; *(crypto+i) != 0x00; i++)
        len++;

    return len;
}

/** \brief Decrypts crypto with 128 bit key into message
 * Uses symmetric key cryptography (AES algorithm) to
 * decrypt a message encrypted with the same algorithm
 * and key. Only two associates sharing the same key
 * will be able to communicate
 */
int decryptAES(unsigned char *crypto, unsigned char *decrypt, unsigned char *key){
    /* Create Key */
    AES_KEY decrypt_key;
    AES_set_decrypt_key(
            key,
            128,
            &decrypt_key
    );

    AES_decrypt(crypto, decrypt, &decrypt_key);
    return strlen(decrypt);
}

/** \brief generates random N-byte key
 */
unsigned char * generateAESkey(int N){
    unsigned char *key;
    int i; //key length
    key = (unsigned char *) malloc(N*sizeof(char));

    for (i=0; i < N; i++){
        key[i] = rand()%0xFF;
    }

    return key;
    
}
