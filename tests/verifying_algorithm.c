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


void
hashdata(unsigned char *PublicKey, char *msg, unsigned int pbytes,
    unsigned char** comm1, unsigned char** comm2, uint8_t* HashResp, int hlen,
    int dlen, uint8_t *data, uint8_t *cHash, int cHashLength)
{
    memcpy(data, PublicKey, 4*2*pbytes);
    memcpy(data + 4*2*pbytes, msg, MSG_LEN);
    int r;
    for (r=0; r<NUM_ROUNDS; r++) {
        memcpy(data + (4*2*pbytes) + (MSG_LEN) + (r * 2*pbytes), comm1[r], 2*pbytes);
        memcpy(data + (4*2*pbytes) + (MSG_LEN) + (NUM_ROUNDS * 2*pbytes) + (r * 2*pbytes),
            comm2[r], 2*pbytes);
    }
    memcpy(data + (4*2*pbytes) + (MSG_LEN) + (2 * NUM_ROUNDS * 2*pbytes), HashResp,
        2 * NUM_ROUNDS * hlen);

    keccak(data, dlen, cHash, cHashLength);
}


struct Signature {
    unsigned char *Commitments1[NUM_ROUNDS];
    unsigned char *Commitments2[NUM_ROUNDS];
    unsigned char *HashResp;
    unsigned char *Randoms[NUM_ROUNDS];
    point_proj *psiS[NUM_ROUNDS];
};


typedef struct thread_params_verify {
    PCurveIsogenyStruct *CurveIsogeny;
    unsigned char *PublicKey;
    struct Signature *sig;

    int cHashLength;
    uint8_t *cHash;

    unsigned int pbytes;
    unsigned int n;
    unsigned int obytes;
} thread_params_verify;

void *verify_thread(void *TPV) {
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    thread_params_verify *tpv = (thread_params_verify*) TPV;

    // iterate through cHash bits as challenge and verify
    bool verified = true;
    int r=0;
    int i,j;

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

        //printf("\nround: %d ", CUR_ROUND);
        i = r/8;
        j = r%8;

        int bit = tpv->cHash[i] & (1 << j);  //challenge bit

        if (bit == 0) {
            printf("round %d: bit 0 - ", r);

            // Check R, phi(R) has order 2^372 (suffices to check that the
            // random number is even)
            uint8_t lastbyte = ((uint8_t*) tpv->sig->Randoms[r])[0];
            if (lastbyte % 2) {
                printf("ERROR: R, phi(R) are not full order\n");
            } else {
                //printf("checked order. ");
            }

            // Check kernels
            f2elm_t A;
            unsigned char *TempPubKey;
            TempPubKey = (unsigned char*)calloc(1, 4*2*tpv->pbytes);

            Status = KeyGeneration_A(tpv->sig->Randoms[r], TempPubKey,
                *(tpv->CurveIsogeny), false);
            if(Status != CRYPTO_SUCCESS) {
                printf("Computing E -> E/<R> failed");
            }

            to_fp2mont(((f2elm_t*)TempPubKey)[0], A);

            int cmp = memcmp(A, tpv->sig->Commitments1[r], sizeof(f2elm_t));
            if (cmp != 0) {
                verified = false;
                printf("verifying E -> E/<R> failed\n");
            }


            unsigned char *TempSharSec;
            TempSharSec = (unsigned char*)calloc(1, 2*tpv->pbytes);

            Status = SecretAgreement_A(tpv->sig->Randoms[r], tpv->PublicKey,
                TempSharSec, *(tpv->CurveIsogeny), NULL);
            if(Status != CRYPTO_SUCCESS) {
                printf("Computing E/<S> -> E/<R,S> failed");
            }

            cmp = memcmp(TempSharSec, tpv->sig->Commitments2[r], 2*tpv->pbytes);
            if (cmp != 0) {
                verified = false;
                printf("verifying E/<S> -> E/<R,S> failed\n");
            }
            free(TempPubKey);
            free(TempSharSec);

        } else {
            printf("round %d: bit 1 - ", r);

            // Check psi(S) has order 3^239 (need to triple it 239 times)
            point_proj_t triple = {0};
            copy_words((digit_t*)tpv->sig->psiS[r], (digit_t*)triple,
                2*2*NWORDS_FIELD);

            f2elm_t A,C={0};
            to_fp2mont(((f2elm_t*)tpv->PublicKey)[0],A);
            fpcopy751((*(tpv->CurveIsogeny))->C, C[0]);
            int t;
            for (t=0; t<238; t++) {
                xTPL(triple, triple, A, C);
                if (is_felm_zero(((felm_t*)triple->Z)[0]) &&
                    is_felm_zero(((felm_t*)triple->Z)[1]))
                {
                    printf("ERROR: psi(S) has order 3^%d\n", t+1);
                }
            }

            unsigned char *TempSharSec, *TempPubKey;
            TempSharSec = calloc(1, 2*tpv->pbytes);
            TempPubKey = calloc(1, 4*2*tpv->pbytes);
            from_fp2mont(tpv->sig->Commitments1[r], ((f2elm_t*)TempPubKey)[0]);

            Status = SecretAgreement_B(NULL, TempPubKey, TempSharSec,
                *(tpv->CurveIsogeny), tpv->sig->psiS[r], NULL);
            if(Status != CRYPTO_SUCCESS) {
                printf("Computing E/<R> -> E/<R,S> failed");
            }

            int cmp = memcmp(TempSharSec, tpv->sig->Commitments2[r],
                2*tpv->pbytes);
            if (cmp != 0) {
                verified = false;
                printf("verifying E/<R> -> E/<R,S> failed\n");
            }
            free(TempPubKey);
            free(TempSharSec);
        }
    }

    if (!verified) {
        printf("ERROR: verify failed.\n");
    }
}


CRYPTO_STATUS
isogeny_verify(PCurveIsogenyStaticData CurveIsogenyData,
        unsigned char *PublicKey, struct Signature *sig, char *msg)
{
    // Number of bytes in a field element
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;
   // Number of bytes in an element in [1, order]
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2, totcycles=0;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;

    int r;

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        //goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test,
        CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        //goto cleanup;
    }

    // compute challenge hash
    int HashLength = 32;
    int cHashLength = NUM_ROUNDS/8;
    int DataLength = (4*2*pbytes) + MSG_LEN + (2 * NUM_ROUNDS * 2*pbytes) +
        (2 * NUM_ROUNDS * HashLength*sizeof(uint8_t));
    uint8_t *datastring, *cHash;
    datastring = calloc(1, DataLength);
    cHash = calloc(1, cHashLength);

    hashdata(PublicKey, msg, pbytes, sig->Commitments1, sig->Commitments2, sig->HashResp,
        HashLength, DataLength, datastring, cHash, cHashLength);

    printf("\nChallenge hash: ");
    print_hash(cHash, cHashLength);

    printf("\nhashed\n");

    // Run the verifying rounds
    pthread_t verify_threads[NUM_THREADS];
    CUR_ROUND = 0;
    if (pthread_mutex_init(&RLOCK, NULL)) {
        printf("ERROR: mutex init failed\n");
        return 1;
    }
    thread_params_verify tpv = {&CurveIsogeny, PublicKey, sig, cHashLength,
        cHash, pbytes, n, obytes};

    int t;
    for (t=0; t<NUM_THREADS; t++) {
        if (pthread_create(&verify_threads[t], NULL, verify_thread, &tpv)) {
            printf("ERROR: Failed to create thread %d\n", t);
        }
    }

    for (t=0; t<NUM_THREADS; t++) {
        pthread_join(verify_threads[t], NULL);
    }

cleanup:
    SIDH_curve_free(CurveIsogeny);
    free(datastring);
    free(cHash);

    return Status;
}

int
read_sigfile(struct Signature *sig, unsigned int pbytes, unsigned int obytes)
{
    int sig_fd;
    unsigned int siglen = NUM_ROUNDS * (4*pbytes + obytes + sizeof(point_proj) +
                                (NUM_ROUNDS * 32 * sizeof(uint8_t)));
    unsigned char *sig_serialized;
    sig_serialized = calloc(1, siglen);

    unsigned int unitlen = 4*pbytes + obytes + sizeof(point_proj);
    int r;


    if ((sig_fd = open("signature", O_RDONLY)) == -1)
    {
        perror("Could not open signature file for reading");
        return -1;
    }
    if ((read(sig_fd, (void *) sig_serialized, siglen)) == -1)
    {
        perror("Could not read from signature file");
        return -1;
    }

    for (r = 0; r < NUM_ROUNDS; r++)
    {
        sig->Commitments1[r] = calloc(1, 2*pbytes);
        sig->Commitments2[r] = calloc(1, 2*pbytes);
        sig->Randoms[r] = calloc(1, obytes);
        sig->psiS[r] = calloc(1, sizeof(point_proj));

        memcpy(sig->Commitments1[r], sig_serialized + (r * unitlen), 2*pbytes);
        memcpy(sig->Commitments2[r], sig_serialized + (r * unitlen) + 2*pbytes,
            2*pbytes);
        memcpy(sig->Randoms[r], sig_serialized + (r * unitlen) + 4*pbytes,
            obytes);
        memcpy(sig->psiS[r], sig_serialized + (r * unitlen) + 4*pbytes + obytes,
            sizeof(point_proj));
    }
    sig->HashResp = calloc(1, 2*NUM_ROUNDS*32*sizeof(uint8_t));
    memcpy(sig->HashResp, sig_serialized + (NUM_ROUNDS * unitlen),
        2 * NUM_ROUNDS * 32 * sizeof(uint8_t));

    free (sig_serialized);
    return 0;

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

    // Number of bytes in a field element
    unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7)/8;
    // Number of bytes in an element in [1, order]
    unsigned int n, obytes = (CurveIsogeny_SIDHp751.owordbits + 7)/8;
    unsigned long long cycles1, cycles2, vcycles;
    int pub_fd, sig_fd;

    // Allocate space for public key
    unsigned char *PublicKey;
    PublicKey = (unsigned char*)calloc(1, 4*2*pbytes); // 4 elements in GF(p^2)

    struct Signature sig;

    // msg XXX: read from file or as commandlineparameter
    char *msg;
    msg = calloc(1, MSG_LEN);
    strncpy(msg, "Hi Bob!", MSG_LEN-1);

    if ((pub_fd = open("public.key", O_RDONLY)) == -1)
    {
        perror("Could not open public.key for reading");
        return EXIT_FAILURE;
    }
    if ((read(pub_fd, PublicKey, 4*2*pbytes)) == -1)
    {
        perror("Could not read from public.key");
        return EXIT_FAILURE;
    }

    // read signature from signature file
    if ((read_sigfile(&sig, pbytes, obytes)) != 0)
    {
        perror("Could not read signature data from signature file");
        return EXIT_FAILURE;
    }

    cycles1 = cpucycles();
    Status = isogeny_verify(&CurveIsogeny_SIDHp751, PublicKey, &sig, msg);
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n",
            SIDH_get_error_message(Status));
        return false;
    }
    cycles2 = cpucycles();
    vcycles = cycles2 - cycles1;

    printf("Verifying .......... %10lld cycles\n\n", vcycles);


    clear_words((void*)PublicKey, NBYTES_TO_NWORDS(4*2*pbytes));

    free(PublicKey);
    free(msg);

    int r;
    for(r=0; r<NUM_ROUNDS; r++)
    {
        free(sig.Randoms[r]);
        free(sig.Commitments1[r]);
        free(sig.Commitments2[r]);
        free(sig.psiS[r]);
    }
    free(sig.HashResp);

    return EXIT_SUCCESS;
}




