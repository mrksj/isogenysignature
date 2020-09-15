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



// Benchmark and test parameters
#define BENCH_LOOPS       10      // Number of iterations per bench
#define TEST_LOOPS        10      // Number of iterations per test
#define NUM_ROUNDS       248
#define MSG_LEN         1024      // XXX: not so clean

int NUM_THREADS = 1;
int CUR_ROUND = 0;
pthread_mutex_t RLOCK;

struct Signature {
    unsigned char *Commitments1[NUM_ROUNDS];
    unsigned char *Commitments2[NUM_ROUNDS];
    unsigned char *HashResp;
    unsigned char *Randoms[NUM_ROUNDS];
    point_proj *psiS[NUM_ROUNDS];
};

typedef struct thread_params_sign {
    PCurveIsogenyStruct *CurveIsogeny;
    unsigned char *PrivateKey;
    unsigned char *PublicKey;
    struct Signature *sig;

    unsigned int pbytes;
    unsigned int n;
    unsigned int obytes;
} thread_params_sign;


void *sign_thread(void *TPS) {
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    thread_params_sign *tps = (thread_params_sign*) TPS;

    int r=0;

    while (1) {
        int stop=0;

        pthread_mutex_lock(&RLOCK);
        if (CUR_ROUND >= NUM_ROUNDS) {
            stop=1;
        } else {
            r = CUR_ROUND;
            CUR_ROUND++;
        }
        pthread_mutex_unlock(&RLOCK);

        if (stop) break;

        //printf("round: %d\n", CUR_ROUND);


        //cycles1 = cpucycles();

        tps->sig->Randoms[r] = (unsigned char*)calloc(1, tps->obytes); // 48 bytes (384bit)
        tps->sig->Commitments1[r] = (unsigned char*)calloc(1, 2*tps->pbytes);
        tps->sig->Commitments2[r] = (unsigned char*)calloc(1, 2*tps->pbytes);
        tps->sig->psiS[r] = calloc(1, sizeof(point_proj));

        // Pick random point R and compute E/<R>
        f2elm_t A;

        unsigned char *TempPubKey;
        TempPubKey = (unsigned char*)calloc(1, 4*2*tps->pbytes);

        Status = KeyGeneration_A(tps->sig->Randoms[r], TempPubKey, *(tps->CurveIsogeny), true);
        if(Status != CRYPTO_SUCCESS) {
            printf("Random point generation failed");
        }

        to_fp2mont(((f2elm_t*)TempPubKey)[0], A);
        fp2copy751(A, *(f2elm_t*)tps->sig->Commitments1[r]);

        ////////////////////////////
        //TODO: compute using A instead
        Status = SecretAgreement_B(tps->PrivateKey, TempPubKey, tps->sig->Commitments2[r], *(tps->CurveIsogeny), NULL, tps->sig->psiS[r]);
        if(Status != CRYPTO_SUCCESS) {
            printf("Random point generation failed");
        }

        //cycles2 = cpucycles();
        //cycles = cycles2 - cycles1;
        //printf("ZKP round %d ran in ............ %10lld cycles\n", r, cycles);
        //totcycles += cycles;

        free(TempPubKey);
    }
}


void
hashdata(unsigned char *PublicKey, char *msg, unsigned int pbytes,
    unsigned char** comm1, unsigned char** comm2, uint8_t* HashResp, int hlen,
    int dlen, uint8_t *data, uint8_t *cHash, int cHashLength)
{
    memcpy(data, PublicKey, 4*2*pbytes);
    memcpy(data + 4*2*pbytes, msg, MSG_LEN);
    int r;
    for (r=0; r<NUM_ROUNDS; r++) {
        memcpy(data + (4*2*pbytes) + (r * 2*pbytes), comm1[r], 2*pbytes);
        memcpy(data + (4*2*pbytes) + (NUM_ROUNDS * 2*pbytes) + (r * 2*pbytes),
            comm2[r], 2*pbytes);
    }
    memcpy(data + (4*2*pbytes) + (2 * NUM_ROUNDS * 2*pbytes), HashResp,
        2 * NUM_ROUNDS * hlen);

    keccak(data, dlen, cHash, cHashLength);
}


CRYPTO_STATUS
isogeny_sign(PCurveIsogenyStaticData CurveIsogenyData,
        unsigned char *PrivateKey, unsigned char *PublicKey,
        struct Signature *sig, char *msg)
{
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2, totcycles=0;

    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        //goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        //goto cleanup;
    }

    // Run the ZKP rounds
    int r;
    pthread_t sign_threads[NUM_THREADS];
    CUR_ROUND = 0;
    if (pthread_mutex_init(&RLOCK, NULL)) {
        printf("ERROR: mutex init failed\n");
        return 1;
    }
    thread_params_sign tps = {&CurveIsogeny, PrivateKey, PublicKey, sig, pbytes, n, obytes};

    int t;
    for (t=0; t<NUM_THREADS; t++) {
        if (pthread_create(&sign_threads[t], NULL, sign_thread, &tps)) {
            printf("ERROR: Failed to create thread %d\n", t);
        }
    }

    for (t=0; t<NUM_THREADS; t++) {
        pthread_join(sign_threads[t], NULL);
    }

    //printf("Average time for ZKP round ...... %10lld cycles\n", totcycles/NUM_ROUNDS);


    // Commit to responses (hash)
    int HashLength = 32; //bytes
    sig->HashResp = calloc(2*NUM_ROUNDS, HashLength*sizeof(uint8_t));
    for (r=0; r<NUM_ROUNDS; r++) {
        keccak((uint8_t*) sig->Randoms[r], obytes, sig->HashResp+((2*r)*HashLength), HashLength);
        keccak((uint8_t*) sig->psiS[r], sizeof(point_proj), sig->HashResp+((2*r+1)*HashLength), HashLength);
    }

    // Create challenge hash (by hashing all the commitments and HashResps)
    uint8_t *datastring, *cHash;
    // DataLength: pk, m, (com_i), (ch_i,j), h_i,j
    int DataLength = (4*2*pbytes) + MSG_LEN + (2 * NUM_ROUNDS * 2*pbytes) +
        (2 * NUM_ROUNDS * HashLength*sizeof(uint8_t));
    int cHashLength = NUM_ROUNDS/8;
    datastring = calloc(1, DataLength);
    cHash = calloc(1, cHashLength);

    //print_hash(cHash);

    hashdata(PublicKey, msg, pbytes, sig->Commitments1, sig->Commitments2, sig->HashResp, HashLength, DataLength, datastring, cHash, cHashLength);

    printf("\nChallenge hash: ");
    print_hash(cHash, cHashLength);

    printf("\nhashed\n");



cleanup:
    SIDH_curve_free(CurveIsogeny);
    free(datastring);
    free(cHash);

    return Status;
}


// Optional parameters: #threads, #rounds
int main(int argc, char *argv[])
{
    NUM_THREADS = 1;

    if (argc > 1) {
        NUM_THREADS = atoi(argv[1]);
    }

    printf("NUM_THREADS: %d\n", NUM_THREADS);

    CRYPTO_STATUS Status = CRYPTO_SUCCESS;

    unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7)/8;      // Number of bytes in a field element
    unsigned int n, obytes = (CurveIsogeny_SIDHp751.owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    unsigned long long cycles1, cycles2, scycles;
    int priv_fd, pub_fd, sig_fd;

    // Allocate space for keys
    unsigned char *PrivateKey, *PublicKey;
    PrivateKey = (unsigned char*)calloc(1, obytes);        // One element in [1, order]
    PublicKey = (unsigned char*)calloc(1, 4*2*pbytes);     // Four elements in GF(p^2)

    struct Signature sig;
    unsigned int siglen = NUM_ROUNDS * (4*pbytes + obytes + sizeof(point_proj) +
                                (NUM_ROUNDS * 32 * sizeof(uint8_t)));
    printf("siglen: %d\n", siglen);

    // msg XXX: read from file or as commandlineparameter
    char *msg;
    msg = calloc(1, MSG_LEN);
    strncpy(msg, "Hi Bob!", MSG_LEN-1);

    // read Keys from public.key and pricate.key
    if ((priv_fd=open("private.key", O_RDONLY)) == -1)
    {
        perror("Could not open private.key for reading");
        return EXIT_FAILURE;
    }
    if ((read(priv_fd, PrivateKey, obytes)) == -1)
    {
        perror("Could not read from private.key");
        close(priv_fd);
        return EXIT_FAILURE;
    }
    close(priv_fd);

    if ((pub_fd=open("public.key", O_RDONLY)) == -1)
    {
        perror("Could not open public.key for reading");
        return EXIT_FAILURE;
    }
    if ((read(pub_fd, PublicKey, 4*2*pbytes)) == -1)
    {
        perror("Could not read from public.key");
        close(pub_fd);
        return EXIT_FAILURE;
    }
    close(pub_fd);

    // compute signature
    cycles1 = cpucycles();
    Status = isogeny_sign(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey, &sig, msg);
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }
    cycles2 = cpucycles();
    scycles = cycles2 - cycles1;

    printf("Signing ............ %10lld cycles\n", scycles);

    // write signature to file
    if ((sig_fd = open("signature", O_WRONLY | O_CREAT,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
    {
        perror("Could not open signature file for writing");
        return EXIT_FAILURE;
    }
    if ((write(sig_fd, (const void*) &sig, siglen)) == -1)
    {
        perror("Could not write sig struct to signature file");
        return EXIT_FAILURE;
    }


    clear_words((void*)PrivateKey, NBYTES_TO_NWORDS(obytes));
    clear_words((void*)PublicKey, NBYTES_TO_NWORDS(4*2*pbytes));

    free(PrivateKey);
    free(PublicKey);
    free(msg);

    int i;
    for(i=0; i<NUM_ROUNDS; i++)
    {
        free(sig.Randoms[i]);
        free(sig.Commitments1[i]);
        free(sig.Commitments2[i]);
        free(sig.psiS[i]);
    }
    free(sig.HashResp);

    return EXIT_SUCCESS;
}




