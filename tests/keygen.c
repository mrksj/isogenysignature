#include "../SIDH.h"
#include "test_extras.h"
#if (OS_TARGET != OS_BSD)
#include <malloc.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include "../keccak.c"
#include "../sha256.c"
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// Benchmark and test parameters
#define BENCH_LOOPS       10	// Number of iterations per bench
#define TEST_LOOPS        10	// Number of iterations per test
#define NUM_ROUNDS       248

int NUM_THREADS = 1;
int CUR_ROUND = 0;
pthread_mutex_t RLOCK;

CRYPTO_STATUS isogeny_keygen(PCurveIsogenyStaticData CurveIsogenyData,
			     unsigned char *PrivateKey,
			     unsigned char *PublicKey)
{
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7) / 8;	// Number of bytes in a field element
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7) / 8;	// Number of bytes in an element in [1, order]
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
    cycles1 = cpucycles();
    Status = KeyGeneration_B(PrivateKey, PublicKey, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {
	passed = false;
    }
    cycles2 = cpucycles();
    cycles = cycles2 - cycles1;
    if (passed) {
	//printf("  Key generated in ................... %10lld cycles", cycles);
    } else {
	printf("  Key generation failed");
	goto cleanup;
    }
    printf("\n");



  cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}

void serialize_keys (unsigned char *priv_key, unsigned char *pub_key,
        int priv_len, int pub_len)
{
    int i;
    FILE *priv_fd, *pub_fd;
    char *priv_key_str, *pub_key_str;
    char *ptr;

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

int main(int argc, char *argv[])
{
    NUM_THREADS = 1;
    printf("NUM_THREADS: %d\n", NUM_THREADS);
    srand(time(0));

    CRYPTO_STATUS Status = CRYPTO_SUCCESS;

    // Number of bytes in a field element
    unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7) / 8;
    // Number of bytes in an element in [1, order]
    unsigned int n, obytes = (CurveIsogeny_SIDHp751.owordbits + 7) / 8;
    unsigned long long cycles1, cycles2, kgcycles;

    // Allocate space for keys
    unsigned char *PrivateKey, *PublicKey;
    PrivateKey = calloc(1, obytes);	// One element in [1, order]
    PublicKey = calloc(1, 4 * 2 * pbytes);	// Four elements in GF(p^2)

    // Generate Keys and measure time
    cycles1 = cpucycles();
    Status = isogeny_keygen(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey);
    if (Status != CRYPTO_SUCCESS) {
	printf("\n\n   Error detected: %s \n\n",
	       SIDH_get_error_message(Status));
	return EXIT_FAILURE;
    }
    cycles2 = cpucycles();
    kgcycles = cycles2 - cycles1;

    printf("KeyGen ............. %10lld cycles\n", kgcycles);

    serialize_keys(PrivateKey, PublicKey, obytes, 4 * 2 * pbytes);

    // Cleanup
    clear_words((void *) PrivateKey, NBYTES_TO_NWORDS(obytes));
    clear_words((void *) PublicKey, NBYTES_TO_NWORDS(4 * 2 * pbytes));

    free(PrivateKey);
    free(PublicKey);

    return EXIT_SUCCESS;
}
