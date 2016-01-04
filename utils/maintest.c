#include "cryptography.h"

/**
 * Used for testing the functions of the library
 */
int main(){
    srand(time(NULL));
    char *privatefilename = "key.pem";
    char *certfilename = "cert.pem";
    unsigned char *message = "hello";


    unsigned char *signature = (unsigned char *) malloc(2048 * sizeof(char));
    int siglen = SignData(privatefilename, message, signature);

    if (siglen < 0){
        perror("No signature returned");
    }else{
        printf("Signature of length %d:\n", siglen);
    }

    int i;
    for (i = 0; i < siglen; i++){
        printf("0x%02x ", signature[i]);
        if (i%8==7) printf("\n");
    }   
    int valid = 
        VerifyData(certfilename, message, signature, siglen);

    printf("Data is %s\n", valid?"valid":"not valid");

    free(signature);
    
    return 0;
}
