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

//struct Signature {
//    unsigned char *Commitments1[NUM_ROUNDS];
//    unsigned char *Commitments2[NUM_ROUNDS];
//    unsigned char *HashResp;
//    unsigned char *Randoms[NUM_ROUNDS];
//    point_proj *psiS[NUM_ROUNDS];
//};

struct Signature
{
    unsigned char *com[NUM_ROUNDS][2];
    int *ch[NUM_ROUNDS];        //only store ch_i,0 as ch_i,1 is always the opposite
    unsigned char *h[NUM_ROUNDS][2];
    unsigned char *resp[NUM_ROUNDS];
};

struct Responses
{
    unsigned char *R[NUM_ROUNDS];
    point_proj *psiS[NUM_ROUNDS];
};

typedef struct thread_params_sign {
    PCurveIsogenyStruct *CurveIsogeny;
    unsigned char *PrivateKey;
    unsigned char *PublicKey;
    struct Signature *sig;
    struct Responses *resp;

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

        //printf("%d", CUR_ROUND);


        //cycles1 = cpucycles();

        tps->resp->R[r] = calloc(1, tps->obytes); // 48 bytes (384bit)
        if (tps->resp->R[r] == NULL) perror("tps->resp->R[r] calloc");
        tps->resp->psiS[r] = calloc(1, sizeof(point_proj));
        if (tps->resp->psiS[r] == NULL) perror("tps->resp->psiS[r] calloc");
        tps->sig->com[r][0] = calloc(1, 2*tps->pbytes);
        if (tps->sig->com[r][0] == NULL) perror("tps->sig->com[r][0] calloc");
        tps->sig->com[r][1] = calloc(1, 2*tps->pbytes);
        if (tps->sig->com[r][1] == NULL) perror("tps->sig->com[r][1] calloc");
        tps->sig->ch[r] = calloc(1, sizeof(uint8_t));
        if (tps->sig->ch[r] == NULL) perror("tps->sig->ch[r] calloc");

        // Pick random point R and compute E/<R>
        f2elm_t A;

        unsigned char *TempPubKey;
        TempPubKey = (unsigned char*)calloc(1, 4*2*tps->pbytes);

        Status = KeyGeneration_A(tps->resp->R[r], TempPubKey, *(tps->CurveIsogeny), true);
        if(Status != CRYPTO_SUCCESS) {
            printf("Random point generation failed");
        }

        to_fp2mont(((f2elm_t*)TempPubKey)[0], A);
        fp2copy751(A, *(f2elm_t*)tps->sig->com[r][0]);

        ////////////////////////////
        //TODO: compute using A instead
        Status = SecretAgreement_B(tps->PrivateKey, TempPubKey, tps->sig->com[r][1], *(tps->CurveIsogeny), NULL, tps->resp->psiS[r]);
        if(Status != CRYPTO_SUCCESS) {
            printf("Random point generation failed");
        }

        // generate ch_i,j bit 0 or 1
        *tps->sig->ch[r] = rand()%2;                  // ch_i,0

        //cycles2 = cpucycles();
        //cycles = cycles2 - cycles1;
        //printf("ZKP round %d ran in ............ %10lld cycles\n", r, cycles);
        //totcycles += cycles;

        free(TempPubKey);
    }
}


void
hashdata(unsigned char *PublicKey, char *msg, unsigned int pbytes,
    unsigned char* com[NUM_ROUNDS][2], int* ch[NUM_ROUNDS],
    uint8_t* HashResp[NUM_ROUNDS][2], int hlen, int dlen, uint8_t *data,
    uint8_t *cHash, int cHashLength)
{
    memcpy(data, PublicKey, 4*2*pbytes);
    memcpy(data + 4*2*pbytes, msg, MSG_LEN);
    int r;
    for (r=0; r<NUM_ROUNDS; r++) {
        memcpy(data + (4*2*pbytes) + (MSG_LEN) + (r*2*2*pbytes), com[r][0],
                2*pbytes);
        memcpy(data + (4*2*pbytes) + (MSG_LEN) + (r*2*2*pbytes) + (2*pbytes),
                com[r][1], 2*pbytes);
        memcpy(data + (4*2*pbytes) + (MSG_LEN) + (NUM_ROUNDS*2*2*pbytes) +
                (r*sizeof(uint8_t)), ch[r], sizeof(uint8_t));
        memcpy(data + (4*2*pbytes) + (MSG_LEN) + (NUM_ROUNDS*2*2*pbytes) +
                (NUM_ROUNDS*sizeof(uint8_t)) + (r*hlen*sizeof(uint8_t)),
                HashResp[r][0], hlen*sizeof(uint8_t));
        memcpy(data + (4*2*pbytes) + (MSG_LEN) + (NUM_ROUNDS*2*2*pbytes) +
                (NUM_ROUNDS*sizeof(uint8_t)) + (r*hlen*sizeof(uint8_t)) + 
                hlen*sizeof(uint8_t), HashResp[r][0], hlen*sizeof(uint8_t));
    }
    keccak(data, dlen, cHash, cHashLength);
}


CRYPTO_STATUS
isogeny_sign(PCurveIsogenyStaticData CurveIsogenyData,
        unsigned char *PrivateKey, unsigned char *PublicKey,
        struct Signature *sig, char *msg, uint8_t *resplen)
{
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2, totcycles=0;
    struct Responses resp;

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
    thread_params_sign tps = {&CurveIsogeny, PrivateKey, PublicKey, sig, &resp, pbytes, n, obytes};

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
    // h_i,j <-- G(resp_i,j)
    // if ch_i.0 == 0 then put (R,phi(R)) (resp[0][r]) in h[0][r],
    // otherwise put psi(S) in h[0][r]. Put the other value in h[1][r]. 
    int HashLength = 32; //bytes
    for (r=0; r<NUM_ROUNDS; r++) {
        sig->h[r][0] = calloc(1, HashLength*sizeof(uint8_t));
        sig->h[r][1] = calloc(1, HashLength*sizeof(uint8_t));
        if (*sig->ch[r] == 0)
        {
            keccak((uint8_t*)resp.R[r], obytes, sig->h[r][0], HashLength);
            keccak((uint8_t*)resp.psiS[r], sizeof(point_proj),
                    sig->h[r][1], HashLength);
        } else
        {
            keccak((uint8_t*)resp.R[r], obytes, sig->h[r][1], HashLength);
            keccak((uint8_t*)resp.psiS[r], sizeof(point_proj), sig->h[r][0],
                    HashLength);
        }
    }

    // Create challenge hash (by hashing all the commitments and HashResps)
    // J_1 || ... || J_2lambda = H(pk,m,(com_i)_i,(ch_i,j)_i,j,(h_i,j)_i,j)
    uint8_t *datastring, *cHash;
    // DataLength: pk, m, (com_i), (ch_i,j), (h_i,j)
    int DataLength = (4*2*pbytes) + 
                     MSG_LEN + 
                     (2 * NUM_ROUNDS * 2*pbytes) +
                     (2 * NUM_ROUNDS * sizeof(uint8_t)) + 
                     (2 * NUM_ROUNDS * HashLength*sizeof(uint8_t));
    int cHashLength = NUM_ROUNDS/8;         //one char has 8 bit i guess
    datastring = calloc(1, DataLength);
    cHash = calloc(1, cHashLength);

    //print_hash(cHash);

    hashdata(PublicKey, msg, pbytes, sig->com, sig->ch, sig->h, HashLength, DataLength,
            datastring, cHash, cHashLength);

    printf("\nChallenge hash: ");
    print_hash(cHash, cHashLength);

    *resplen = 0;
    for(r=0; r<NUM_ROUNDS; r++)
    {
        int i = r/8;
        int j = r%8;

        int mask = 1 << j;
        int bit = cHash[i] & (1 << j);  //challenge bit

        if (bit == 0 && *sig->ch[r] == 0){
            sig->resp[r] = resp.R[r];
            *resplen += obytes;
            printf("bit0 ch0 resplen:%d\n", *resplen);
        }
        else if (bit == 0 && *sig->ch[r] == 1){
            sig->resp[r] = (unsigned char *)resp.psiS[r];
            *resplen += sizeof(point_proj);
            printf("bit0 ch1 resplen:%d\n", *resplen);
        }
        else if (bit != 0 && *sig->ch[r] == 0){
            sig->resp[r] = (unsigned char *)resp.psiS[r];
            *resplen += sizeof(point_proj);
            printf("bit1 ch0 resplen:%d\n", *resplen);
        }
        else if (bit != 0 && *sig->ch[r] == 1){
            sig->resp[r] = resp.R[r];
            *resplen += obytes;
            printf("bit1 ch1 resplen:%d\n", *resplen);
        }
        else{
            printf("bit and challenge combination not plausible:\n"
                    "bit: %d\t challenge: %d\n", bit, *sig->ch[r]);
        }
    }
    //printf("resplen: %d\n", *resplen);


cleanup:
    SIDH_curve_free(CurveIsogeny);
    free(datastring);
    free(cHash);

    return Status;
}

//int
//write_sigfile(struct Signature sig, unsigned int pbytes, unsigned int obytes)
//{
//    int sig_fd;
//    unsigned int siglen = NUM_ROUNDS * (4*pbytes + obytes + sizeof(point_proj) +
//                                (NUM_ROUNDS * 32 * sizeof(uint8_t)));
//    unsigned char *sig_serialized;
//    sig_serialized = calloc(1, siglen);
//
//    // length of one signature unit consisting of
//    // Commitments1[r], Commitments2[r], Randoms[r] and psiS
//    unsigned int unitlen = 4*pbytes + obytes + sizeof(point_proj);
//
//    int r;
//    for (r=0; r<NUM_ROUNDS; r++)
//    {
//        memcpy(sig_serialized + (r * (unitlen)), sig.Commitments1[r], 2 * pbytes);
//        memcpy(sig_serialized + (r * unitlen) + 2*pbytes,
//            sig.Commitments2[r], 2*pbytes);
//        memcpy(sig_serialized + (r * unitlen) + 4*pbytes, sig.Randoms[r],
//            obytes);
//        memcpy(sig_serialized + (r * unitlen) + 4*pbytes + obytes,
//            sig.psiS[r], sizeof(point_proj));
//
//        free(sig.Randoms[r]);
//        free(sig.Commitments1[r]);
//        free(sig.Commitments2[r]);
//        free(sig.psiS[r]);
//    }
//    memcpy(sig_serialized + (NUM_ROUNDS * unitlen), sig.HashResp,
//            2 * NUM_ROUNDS * 32 * sizeof(uint8_t));
//    free(sig.HashResp);
//
//    if ((sig_fd = open("signature", O_WRONLY | O_CREAT,
//                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
//    {
//        perror("Could not open signature file for writing");
//        return -1;
//    }
//
//    if (write(sig_fd, sig_serialized, siglen) == -1) {
//        perror("Could not write signature to file");
//        return -1;
//    }
//
//    free(sig_serialized);
//
//    return 0;
//}


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
    int priv_fd, pub_fd;
    uint8_t *resplen = calloc(1, sizeof(uint8_t));

    // Allocate space for keys
    unsigned char *PrivateKey, *PublicKey;
    PrivateKey = (unsigned char*)calloc(1, obytes);        // One element in [1, order]
    PublicKey = (unsigned char*)calloc(1, 4*2*pbytes);     // Four elements in GF(p^2)

    struct Signature sig;

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
    Status = isogeny_sign(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey, &sig, msg, resplen);
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }
    cycles2 = cpucycles();
    scycles = cycles2 - cycles1;

    printf("Signing ............ %10lld cycles\n", scycles);
    printf("resplen: %d\n", *resplen);

    // write signature to file
    //if ((write_sigfile(sig, pbytes, obytes)) != 0){
    //    perror("Could not write signature to file");
    //}


    clear_words((void*)PrivateKey, NBYTES_TO_NWORDS(obytes));
    clear_words((void*)PublicKey, NBYTES_TO_NWORDS(4*2*pbytes));

    free(PrivateKey);
    free(PublicKey);
    free(msg);
    free(resplen);


    return EXIT_SUCCESS;
}




