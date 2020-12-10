#if (OS_TARGET != OS_BSD)
    #include <malloc.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "SIDH.h"
#include "SIDH_internal.h"
#include "tests/test_extras.h"
#include "SISig.h"
#include "keccak.h"

pthread_mutex_t RLOCK;
int CUR_ROUND_SIGN = 0;

struct Signature
{
    unsigned char *com[NUM_ROUNDS][2];      //2*NUM_ROUNDS*2*pbytes
    //only store ch_i,0 as ch_i,1 is always the opposite
    uint8_t *ch[NUM_ROUNDS];                    //NUM_ROUNDS*sizeof(int)
    unsigned char *h[NUM_ROUNDS][2];        //2*NUM_ROUNDS*32*sizeof(uint8_t)
    unsigned char *resp[NUM_ROUNDS];        //*resplen
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
    unsigned int obytes;
} thread_params_sign;

void *sign_thread(void *TPS) {
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    thread_params_sign *tps = (thread_params_sign*) TPS;

    int r;

    while (1) {
        int stop=0;

        pthread_mutex_lock(&RLOCK);
        if (CUR_ROUND_SIGN >= NUM_ROUNDS) {
            stop=1;
        } else {
            r = CUR_ROUND_SIGN;
            CUR_ROUND_SIGN++;
        }
        pthread_mutex_unlock(&RLOCK);

        if (stop) break;
        //printf("thread with id: %lu has r: %d\n", pthread_self(), r);


        tps->resp->R[r] = calloc(1, tps->obytes); // 48 bytes (384bit)
        tps->resp->psiS[r] = calloc(1, sizeof(point_proj));
        tps->sig->com[r][0] = calloc(1, 2*tps->pbytes);
        tps->sig->com[r][1] = calloc(1, 2*tps->pbytes);
        tps->sig->ch[r] = calloc(1, sizeof(uint8_t));

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

        // XXX: rand is an unsafe source of randomness
        // generate ch_i,j bit 0 or 1
        *tps->sig->ch[r] = rand()%2;

        free(TempPubKey);
    }
}


CRYPTO_STATUS
isogeny_sign(unsigned char *PrivateKey, unsigned char *PublicKey,
        struct Signature *sig, char *msg, struct Responses *resp, unsigned int *resplen)
{
    unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7)/8;      // Number of bytes in a field element
    unsigned int obytes = (CurveIsogeny_SIDHp751.owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2, totcycles=0;

    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        //goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, &CurveIsogeny_SIDHp751);
    if (Status != CRYPTO_SUCCESS) {
        //goto cleanup;
    }

    // Run the ZKP rounds
    int r;
    CUR_ROUND_SIGN = 0;
    pthread_t sign_threads[NUM_THREADS];
    if (pthread_mutex_init(&RLOCK, NULL)) {
        printf("ERROR: mutex init failed\n");
        return 1;
    }
    thread_params_sign tps = {&CurveIsogeny, PrivateKey, PublicKey, sig, resp, pbytes, obytes};

    int t;
    for (t=0; t<NUM_THREADS; t++) {
        if (pthread_create(&sign_threads[t], NULL, sign_thread, &tps)) {
            printf("ERROR: Failed to create thread %d\n", t);
        }
    }

    for (t=0; t<NUM_THREADS; t++) {
        pthread_join(sign_threads[t], NULL);
    }

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
            keccak((uint8_t*)resp->R[r], obytes, sig->h[r][0], HashLength);
            keccak((uint8_t*)resp->psiS[r], sizeof(point_proj),
                    sig->h[r][1], HashLength);
        } else
        {
            keccak((uint8_t*)resp->R[r], obytes, sig->h[r][1], HashLength);
            keccak((uint8_t*)resp->psiS[r], sizeof(point_proj), sig->h[r][0],
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
    int cHashLength = NUM_ROUNDS/8; //31
    datastring = calloc(1, DataLength);
    cHash = calloc(1, cHashLength);

    hashdata(PublicKey, msg, pbytes, sig->com, sig->ch, sig->h, HashLength, DataLength,
            datastring, cHash, cHashLength);

    printf("\nChallenge hash: ");
    print_hash(cHash, cHashLength);

    *resplen = 0;
    for(r=0; r<NUM_ROUNDS; r++)
    {
        int i = r/8;
        int j = r%8;

        int bit = cHash[i] & (1 << j);  //challenge bit
        if (bit == 0 && *sig->ch[r] == 0){
            sig->resp[r] = resp->R[r];
            *resplen += obytes;
        }
        else if (bit == 0 && *sig->ch[r] == 1){
            sig->resp[r] = (unsigned char *)resp->psiS[r];
            *resplen += sizeof(point_proj);
        }
        else if (bit != 0 && *sig->ch[r] == 0){
            sig->resp[r] = (unsigned char *)resp->psiS[r];
            *resplen += sizeof(point_proj);
        }
        else if (bit != 0 && *sig->ch[r] == 1){
            sig->resp[r] = resp->R[r];
            *resplen += obytes;
        }
        else{
            printf("bit and challenge combination not plausible:\n"
                    "bit: %d\t challenge: %d\n", bit, *sig->ch[r]);
        }
    }


cleanup:
    SIDH_curve_free(CurveIsogeny);
    free(datastring);
    free(cHash);

    return Status;
}

struct SigData *
write_sigdata(struct Signature sig, unsigned int pbytes, unsigned int obytes,
        struct Responses resp, unsigned int resplen)
{
    int sig_fd;
    unsigned int comlen = 2*NUM_ROUNDS*2*pbytes;
    unsigned int chlen = NUM_ROUNDS*sizeof(uint8_t);
    unsigned int hlen = 2*NUM_ROUNDS*32*sizeof(uint8_t);
    unsigned int siglen = comlen + chlen + hlen + resplen;
    unsigned int single_resp_r;
    unsigned char *sig_serialized = calloc(1, siglen);
    struct SigData *sigdata = calloc(1, sizeof(struct SigData));

    unsigned int act_resp_pos = 0;
    int r;
    for (r=0; r<NUM_ROUNDS; r++)
    {
        // if sig.resp[r] points to same location as resp.R[r], it needs obytes
        // space, otherwise it needs sizeof(point_proj) bytes space (384)
        single_resp_r = sig.resp[r] == resp.R[r] ?
            obytes : sizeof(point_proj);

        memcpy(sig_serialized + (r*4*pbytes), sig.com[r][0], 2*pbytes);
        memcpy(sig_serialized + (r*4*pbytes) + 2*pbytes, sig.com[r][1],
                2*pbytes);
        memcpy(sig_serialized + comlen + (r*sizeof(uint8_t)), sig.ch[r],
                sizeof(uint8_t));
        memcpy(sig_serialized + comlen + chlen + (r*2*32*sizeof(uint8_t)),
                sig.h[r][0], 32*sizeof(uint8_t));
        memcpy(sig_serialized + comlen + chlen + (r*2*32*sizeof(uint8_t) +
                32*sizeof(uint8_t)), sig.h[r][1], 32*sizeof(uint8_t));
        memcpy(sig_serialized + comlen + chlen + hlen + act_resp_pos ,
                sig.resp[r], single_resp_r);
        act_resp_pos += single_resp_r;

        free(sig.com[r][0]);
        free(sig.com[r][1]);
        free(sig.ch[r]);
        free(sig.h[r][0]);
        free(sig.h[r][1]);
        free(resp.R[r]);
        free(resp.psiS[r]);
    }

    //if ((sig_fd = open("signature", O_WRONLY | O_CREAT,
    //                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
    //{
    //    perror("Could not open signature file for writing");
    //}

    //if (write(sig_fd, sig_serialized, siglen) == -1) {
    //    perror("Could not write signature to file");
    //}

    sigdata->sig = sig_serialized;
    sigdata->siglen = siglen;
    return sigdata;
}

unsigned char * 
SISig_P751_Read_Privkey(char *file)
{
    int i, j, ret = 0;
    FILE *priv_fd;
    char *line = NULL;
    size_t n = 0;
    ssize_t read;
    char * ptr;
    unsigned char *PrivateKey = calloc(1, PRIV_KEY_LEN);

    if ((priv_fd=fopen(file, "r")) == NULL){
        printf("failed to open private.key");
        ret = -1;
        goto cleanup;
    }

    i = 0;
    while ((read = getline(&line, &n, priv_fd)) != -1){
        switch (i){
            case 0:
                if (strncmp(line, "-----BEGIN SISIG PRIVATE KEY-----", 33) != 0){
                    printf("invalid private.key format\n");
                    ret = -1;
                }
                break;
            case 1:
                if (read != 2 * PRIV_KEY_LEN + 1){
                    printf("private key too short\n");
                    ret = -1;
                }
                ptr = line;
                for (j = 0; j < PRIV_KEY_LEN; j++){
                    sscanf(ptr, "%2hhx", &PrivateKey[j]);
                    ptr += 2;
                }
                break;
            case 2:
                if (strncmp(line, "-----END SISIG PRIVATE KEY-----", 31) != 0){
                    printf("invalid private.key format\n");
                    ret = -1;
                }
                break;
            default:
                printf("why do we read more than 3 lines?\n");
                ret = -1;
                break;
        }
        i += 1;
    }
cleanup:
    fclose(priv_fd);
    free(line);
    return ret == -1 ? NULL : PrivateKey;
}
    
unsigned char*
SISig_P751_Read_Pubkey(char *file)
{
    int i, j, ret = 0;
    FILE *pub_fd;
    char *line = NULL;
    size_t n = 0;
    ssize_t read;
    char * ptr;
    unsigned char *PublicKey = calloc(1, PUB_KEY_LEN);


    if ((pub_fd=fopen(file, "r")) == NULL){
        printf("failed to open public.key\n");
        ret = -1;
        goto cleanup;
    }

    i = 0;
    while ((read = getline(&line, &n, pub_fd)) != -1){
        switch (i){
            case 0:
                if (strncmp(line, "-----BEGIN SISIG PUBLIC KEY-----", 32) != 0){
                    printf("invalid public.key format(first line)\n");
                    ret = -1;
                    goto cleanup;
                }
                break;
            case 1:
                if (read != 2 * PUB_KEY_LEN + 1){
                    printf("public key too short\n");
                    ret = -1;
                    goto cleanup;
                }
                ptr = line;
                for (j = 0; j < PUB_KEY_LEN; j++){
                    sscanf(ptr, "%2hhx", &PublicKey[j]);
                    ptr += 2;
                }
                break;
            case 2:
                if (strncmp(line, "-----END SISIG PUBLIC KEY-----", 30) != 0){
                    printf("invalid public.key format(last line)\n");
                    ret = -1;
                    goto cleanup;
                }
                break;
            default:
                printf("why do we read more than 3 lines?\n");
                ret = -1;
                goto cleanup;
                break;
        }
        i += 1;
    }
cleanup:
    fclose(pub_fd);
    free(line);
    return ret == -1 ? NULL : PublicKey;
}

struct SigData *
SISig_P751_Sign (char *msg, unsigned char *PrivateKey,
        unsigned char *PublicKey)
{
    struct Signature *sig = calloc(1, sizeof(struct Signature));
    struct Responses *resp = calloc(1, sizeof(struct Responses));
    unsigned int *resplen = calloc(1, sizeof(unsigned int));
    unsigned char *signature;
    struct SigData *sigdata;


    if(isogeny_sign(PrivateKey, PublicKey, sig, msg, resp, resplen) != 0)
        return NULL;
    if ((sigdata = write_sigdata(*sig, PBYTES, OBYTES, *resp,
                *resplen)) == NULL)
        return NULL;

    free(resp);
    free(resplen);
    free(sig);
    return sigdata;

}
