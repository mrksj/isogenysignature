#if (OS_TARGET != OS_BSD)
#include <malloc.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "SIDH.h"
#include "tests/test_extras.h"
#include "SISig.h"


CRYPTO_STATUS
isogeny_keygen( unsigned char *PrivateKey, unsigned char *PublicKey)
{
    PCurveIsogenyStaticData CurveIsogenyData;
    unsigned int pbytes = PBYTES;	// Number of bytes in a field element
    unsigned int n, obytes = OBYTES;	// Number of bytes in an element in [1, order]
    bool valid_PublicKey = false;
    PCurveIsogenyStruct CurveIsogeny = { 0 };
    unsigned long long cycles, cycles1, cycles2;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;


    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
	Status = CRYPTO_ERROR_NO_MEMORY;
	goto cleanup;
    }
    Status =
	SIDH_curve_initialize(CurveIsogeny, &random_bytes_test,
			      CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
	goto cleanup;
    }

    // Generate Peggy(Bob)'s keys
    passed = true;
    Status = KeyGeneration_B(PrivateKey, PublicKey, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {
	passed = false;
    }
    if (!passed) {
	    printf("  Key generation failed");
	    goto cleanup;
    }
    printf("\n");



  cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}

void serialize_keys (unsigned char *priv_key, unsigned char *pub_key)
{
    int i;
    FILE *priv_fd, *pub_fd;
    char *priv_key_str, *pub_key_str;
    char *ptr;
    int priv_len = PRIV_KEY_LEN, pub_len = PUB_KEY_LEN;

    priv_key_str = calloc(1, 2 * priv_len + 1); //each byte needs two byte in hex + \0
    pub_key_str = calloc(1, 2 * pub_len + 1);
    ptr = priv_key_str;
    for (i = 0; i < priv_len; i++)
    {
        sprintf(ptr, "%02x", priv_key[i]);
        ptr += 2;
    }
    priv_key_str[2*priv_len] = '\0';
    ptr = pub_key_str;
    for (i = 0; i < pub_len; i++)
    {
        sprintf(ptr, "%02x", pub_key[i]);
        ptr += 2;
    }
    pub_key_str[2*pub_len] = '\0';
    // Write generated keys to files
    if ((priv_fd = fopen("private.key", "w")) == NULL) {
	perror("Could not open private.key for writing");
    }
    if (fputs("-----BEGIN SISIG PRIVATE KEY-----\n", priv_fd) == EOF){
        perror("failed writing private key to file");
    }
    if (fputs(priv_key_str, priv_fd) == EOF){
        perror("failed writing private key to file");
    }
    if (fputs("\n-----END SISIG PRIVATE KEY-----\n", priv_fd) == EOF){
        perror("failed writing private key to file");
    }
    fclose(priv_fd);
    if ((pub_fd = fopen("public.key", "w")) == NULL) {
	perror("Could not open public.key for writing");
    }
    if (fputs("-----BEGIN SISIG PUBLIC KEY-----\n", pub_fd) == EOF){
        perror("failed writing public key to file");
    }
    if (fputs(pub_key_str, pub_fd) == EOF){
        perror("failed writing public key to file");
    }
    if (fputs("\n-----END SISIG PUBLIC KEY-----\n", pub_fd) == EOF){
        perror("failed writing public key to file");
    }
    fclose(pub_fd);

    free(priv_key_str);
    free(pub_key_str);
}

int SISig_P751_Keygen(unsigned char *PrivateKey, unsigned char *PublicKey)
{
    if(isogeny_keygen(PrivateKey, PublicKey) != 0)
        return -1;
    serialize_keys(PrivateKey, PublicKey);
    return 0;
}
