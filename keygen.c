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
    unsigned int pbytes = PBYTES;	// Number of bytes in a field element
    unsigned int n, obytes = OBYTES;	// Number of bytes in an element in [1, order]
    bool valid_PublicKey = false;
    PCurveIsogenyStruct CurveIsogeny = { 0 };
    unsigned long long cycles, cycles1, cycles2;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;


    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
    if (CurveIsogeny == NULL) {
	Status = CRYPTO_ERROR_NO_MEMORY;
	goto cleanup;
    }
    Status =
	SIDH_curve_initialize(CurveIsogeny, &random_bytes_test,
			      &CurveIsogeny_SIDHp751);
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

int
SISig_P751_Write_Privkey(unsigned char *PrivateKey, char *file)
{
    int i, ret=0;
    FILE *priv_fd;
    char *priv_key_str;
    char *ptr;
    
    priv_key_str = calloc(1, 2 * PRIV_KEY_LEN + 1); //each byte needs two byte in hex + \0
    ptr = priv_key_str;
    for (i = 0; i < PRIV_KEY_LEN; i++)
    {
        sprintf(ptr, "%02x", PrivateKey[i]);
        ptr += 2;
    }
    priv_key_str[2*PRIV_KEY_LEN] = '\0';

    if ((priv_fd = fopen(file, "w")) == NULL) {
	    printf("Could not open private.key for writing\n");
    }
    if (fputs("-----BEGIN SISIG PRIVATE KEY-----\n", priv_fd) == EOF){
        printf("failed writing private key to file\n");
        ret = -1;
        goto cleanup;
    }
    if (fputs(priv_key_str, priv_fd) == EOF){
        printf("failed writing private key to file\n");
        ret = -1;
        goto cleanup;
    }
    if (fputs("\n-----END SISIG PRIVATE KEY-----\n", priv_fd) == EOF){
        printf("failed writing private key to file\n");
        ret = -1;
        goto cleanup;
    }
cleanup:
    fclose(priv_fd);
    free(priv_key_str);
    return ret;
}

int
SISig_P751_Write_Pubkey(unsigned char *PublicKey, char *file)
{
    int i, ret=0;
    FILE *pub_fd;
    char *pub_key_str;
    char *ptr;
    
    pub_key_str = calloc(1, 2 * PUB_KEY_LEN + 1); //each byte needs two byte in hex + \0
    ptr = pub_key_str;
    for (i = 0; i < PUB_KEY_LEN; i++)
    {
        sprintf(ptr, "%02x", PublicKey[i]);
        ptr += 2;
    }
    pub_key_str[2*PUB_KEY_LEN] = '\0';

    if ((pub_fd = fopen(file, "w")) == NULL) {
	    printf("Could not open private.key for writing\n");
    }
    if (fputs("-----BEGIN SISIG PUBLIC KEY-----\n", pub_fd) == EOF){
        printf("failed writing private key to file\n");
        ret = -1;
        goto cleanup;
    }
    if (fputs(pub_key_str, pub_fd) == EOF){
        printf("failed writing private key to file\n");
        ret = -1;
        goto cleanup;
    }
    if (fputs("\n-----END SISIG PUBLIC KEY-----\n", pub_fd) == EOF){
        printf("failed writing private key to file\n");
        ret = -1;
        goto cleanup;
    }
cleanup:
    fclose(pub_fd);
    free(pub_key_str);
    return ret;
}

int SISig_P751_Keygen(unsigned char *PrivateKey, unsigned char *PublicKey)
{
    if(isogeny_keygen(PrivateKey, PublicKey) != 0)
        return -1;
    return 0;
}
