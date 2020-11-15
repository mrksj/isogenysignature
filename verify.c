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

#include "SIDH.h"
#include "tests/test_extras.h"
#include "SISig.h"
#include "keccak.h"


pthread_mutex_t RLOCK2;

struct Signature
{
    unsigned char *com[NUM_ROUNDS][2];      //2*NUM_ROUNDS*2*pbytes
    //only store ch_i,0 as ch_i,1 is always the opposite
    uint8_t *ch[NUM_ROUNDS];                //NUM_ROUNDS*sizeof(int)
    unsigned char *h[NUM_ROUNDS][2];        //2*NUM_ROUNDS*32*sizeof(uint8_t)
    unsigned char *resp[NUM_ROUNDS];        //*resplen
};


typedef struct thread_params_verify {
    PCurveIsogenyStruct *CurveIsogeny;
    unsigned char *PublicKey;
    struct Signature *sig;

    uint8_t *bit;

    unsigned int pbytes;
    unsigned int n;
    unsigned int obytes;
} thread_params_verify;

void *verify_thread(void *TPV) {
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    thread_params_verify *tpv = (thread_params_verify*) TPV;

    int CUR_ROUND = 0;
    // iterate through cHash bits as challenge and verify
    bool verified = true;
    int r=0;
    int i,j;

    while (1) {
        int stop=0;

        pthread_mutex_lock(&RLOCK2);
        if (CUR_ROUND >= NUM_ROUNDS) {
            stop=1;
        } else {
            r = CUR_ROUND;
            CUR_ROUND++;
        }
        pthread_mutex_unlock(&RLOCK2);

        if (stop) break;

        if (tpv->bit[r] == 0 && *tpv->sig->ch[r] == 0 ||
                tpv->bit[r] == 1 && *tpv->sig->ch[r] == 1) {

            // Check R, phi(R) has order 2^372 (suffices to check that the
            // random number is even)
            uint8_t lastbyte = ((uint8_t*) tpv->sig->resp[r])[0];
            if (lastbyte % 2) {
                printf("ERROR: R, phi(R) are not full order\n");
            }

            // Check kernels
            f2elm_t A;
            unsigned char *TempPubKey;
            TempPubKey = (unsigned char*)calloc(1, 4*2*tpv->pbytes);

            Status = KeyGeneration_A(tpv->sig->resp[r], TempPubKey,
                *(tpv->CurveIsogeny), false);
            if(Status != CRYPTO_SUCCESS) {
                printf("Computing E -> E/<R> failed");
            }

            to_fp2mont(((f2elm_t*)TempPubKey)[0], A);

            int cmp = memcmp(A, tpv->sig->com[r][0], sizeof(f2elm_t));
            if (cmp != 0) {
                verified = false;
                printf("verifying E -> E/<R> failed\n");
            }


            unsigned char *TempSharSec;
            TempSharSec = (unsigned char*)calloc(1, 2*tpv->pbytes);

            Status = SecretAgreement_A(tpv->sig->resp[r], tpv->PublicKey,
                TempSharSec, *(tpv->CurveIsogeny), NULL);
            if(Status != CRYPTO_SUCCESS) {
                printf("Computing E/<S> -> E/<R,S> failed");
            }

            cmp = memcmp(TempSharSec, tpv->sig->com[r][1], 2*tpv->pbytes);
            if (cmp != 0) {
                verified = false;
                printf("verifying E/<S> -> E/<R,S> failed\n");
            }
            free(TempPubKey);
            free(TempSharSec);

        } else {

            // Check psi(S) has order 3^239 (need to triple it 239 times)
            point_proj_t triple = {0};
            copy_words((digit_t*)tpv->sig->resp[r], (digit_t*)triple,
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
            from_fp2mont(tpv->sig->com[r][0], ((f2elm_t*)TempPubKey)[0]);

            Status = SecretAgreement_B(NULL, TempPubKey, TempSharSec,
                *(tpv->CurveIsogeny), (point_proj *)tpv->sig->resp[r], NULL);
            if(Status != CRYPTO_SUCCESS) {
                printf("Computing E/<R> -> E/<R,S> failed");
            }

            int cmp = memcmp(TempSharSec, tpv->sig->com[r][1],
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
        unsigned char *PublicKey, struct Signature *sig, uint8_t *bit)
{
    int NUM_THREADS = 1;
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

    // Run the verifying rounds
    pthread_t verify_threads[NUM_THREADS];
    if (pthread_mutex_init(&RLOCK2, NULL)) {
        printf("ERROR: mutex init failed\n");
        return 1;
    }
    thread_params_verify tpv = {&CurveIsogeny, PublicKey, sig, bit, pbytes, n, obytes};

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

    return Status;
}

int
read_sigfile_cut(int siglen_cut, unsigned char *sig_cut_serialized)
{
    int sig_fd;


    if ((sig_fd = open("signature", O_RDONLY)) == -1)
    {
        perror("Could not open signature file for reading");
        return -1;
    }
    if ((read(sig_fd, (void *) sig_cut_serialized, siglen_cut)) == -1)
    {
        perror("Could not read from signature file");
        return -1;
    }
    return 0;

}

int
gen_chash (unsigned char *sig_cut_serialized, struct Signature *sig,
        unsigned int pbytes, unsigned char *PublicKey, char *msg,
        uint8_t *cHash, int cHashLength)
{
    int r;
    for (r=0; r<NUM_ROUNDS; r++){
        sig->com[r][0] = calloc(1, 2*pbytes);
        sig->com[r][1] = calloc(1, 2*pbytes);
        sig->ch[r] = calloc(1, sizeof(uint8_t));
        sig->h[r][0] = calloc(1, 32*sizeof(uint8_t));
        sig->h[r][1] = calloc(1, 32*sizeof(uint8_t));

        memcpy(sig->com[r][0], sig_cut_serialized + (r*4*pbytes), 2*pbytes);
        memcpy(sig->com[r][1], sig_cut_serialized + (r*4*pbytes) + 2*pbytes,
                2*pbytes);
        memcpy(sig->ch[r], sig_cut_serialized + (NUM_ROUNDS*4*pbytes) +
                (r*sizeof(uint8_t)), sizeof(uint8_t));
        memcpy(sig->h[r][0], sig_cut_serialized + (NUM_ROUNDS*4*pbytes) +
                (NUM_ROUNDS*sizeof(uint8_t)) + (r*2*32*sizeof(uint8_t)),
                32*sizeof(uint8_t));
        memcpy(sig->h[r][1], sig_cut_serialized + (NUM_ROUNDS*4*pbytes) +
                (NUM_ROUNDS*sizeof(uint8_t)) + (r*2*32*sizeof(uint8_t)) +
                (32*sizeof(uint8_t)), 32*sizeof(uint8_t));
    }

    // Create challenge hash (by hashing all the commitments and HashResps)
    // J_1 || ... || J_2lambda = H(pk,m,(com_i)_i,(ch_i,j)_i,j,(h_i,j)_i,j)
    int HashLength = 32;
    uint8_t *datastring;
    // DataLength: pk, m, (com_i), (ch_i,j), (h_i,j)
    int DataLength = (4*2*pbytes) +
                     MSG_LEN +
                     (2 * NUM_ROUNDS * 2*pbytes) +
                     (2 * NUM_ROUNDS * sizeof(uint8_t)) +
                     (2 * NUM_ROUNDS * HashLength*sizeof(uint8_t));
    datastring = calloc(1, DataLength);
    hashdata(PublicKey, msg, pbytes, sig->com, sig->ch, sig->h, HashLength, DataLength,
            datastring, cHash, cHashLength);
    free(datastring);

    printf("\nChallenge hash: ");
    print_hash(cHash, cHashLength);
    return 0;
}


int
parse_sigfile_rest(struct Signature *sig, unsigned int pbytes,
        unsigned int obytes, uint8_t *cHash, uint8_t *bit)
{
    int sig_fd;
    int r;
    unsigned char *buf;
    // offset: just read the responses form the file, that starts after
    // the bits used for com_i,j, ch_i,0, and h_i,j
    unsigned int offset = (2*NUM_ROUNDS*2*pbytes) +
                          (NUM_ROUNDS*sizeof(uint8_t)) +
                          (2*NUM_ROUNDS*32*sizeof(uint8_t));
    unsigned int len = 0;

    // len calculation depends on type of response which can only be figured by
    // looking at the cHash together with the sig->ch[r]
    for (r = 0; r < NUM_ROUNDS; r++){
        int i = r/8;
        int j = r%8;

        bit[r] = cHash[i] & (1 << j) ? 1 : 0;  //challenge bit
        if (bit[r] == 0 && *sig->ch[r] == 0){
            len += obytes;
        }
        else if (bit[r] == 0 && *sig->ch[r] == 1){
            len += sizeof(point_proj);
        }
        else if (bit[r] != 0 && *sig->ch[r] == 0){
            len += sizeof(point_proj);
        }
        else if (bit[r] != 0 && *sig->ch[r] == 1){
            len += obytes;
        }
        else{
            printf("cannot calculate len of rest signature because of invalid"
                    " combination of bit=%d and *sig->ch[r]=%d\n",
                    bit[r], *sig->ch[r]);
            return -1;
        }
    }

    buf = calloc(1, len);

    if ((sig_fd = open("signature", O_RDONLY)) == -1)
    {
        perror("Could not open signature file for reading");
        return -1;
    }
    if ((pread(sig_fd, (void *) buf, len, offset)) == -1)
    {
        perror("Could not read from signature file");
        return -1;
    }

    int act_resp_pos = 0;
    for (r = 0; r < NUM_ROUNDS; r++){
        if (bit[r] == 0 && *sig->ch[r] == 0){
            sig->resp[r] = calloc(1, obytes);
            memcpy(sig->resp[r], buf + act_resp_pos, obytes);
            act_resp_pos += obytes;
        }
        else if (bit[r] == 0 && *sig->ch[r] == 1){
            sig->resp[r] = calloc(1, sizeof(point_proj));
            memcpy(sig->resp[r], buf + act_resp_pos, sizeof(point_proj));
            act_resp_pos += sizeof(point_proj);
        }
        else if (bit[r] != 0 && *sig->ch[r] == 0){
            sig->resp[r] = calloc(1, sizeof(point_proj));
            memcpy(sig->resp[r], buf + act_resp_pos, sizeof(point_proj));
            act_resp_pos += sizeof(point_proj);
        }
        else if (bit[r] != 0 && *sig->ch[r] == 1){
            sig->resp[r] = calloc(1, obytes);
            memcpy(sig->resp[r], buf + act_resp_pos, obytes);
            act_resp_pos += obytes;
        }
        else{
            printf("wrong combination of bit[r]:%d and sig->ch[r]:%d\n"
                    "cannot reassemble responses\n", bit[r], *sig->ch[r]);
            return -1;
        }
    }

    free(buf);
    return 0;
}
int
parse_sig_rest(struct Signature *sig, unsigned char *sig_binary,
        unsigned int pbytes, unsigned int obytes, uint8_t *cHash, uint8_t *bit)
{
    int sig_fd;
    int r;
    unsigned char *buf;
    // offset: just read the responses form the file, that starts after
    // the bits used for com_i,j, ch_i,0, and h_i,j
    unsigned int offset = (2*NUM_ROUNDS*2*pbytes) +
                          (NUM_ROUNDS*sizeof(uint8_t)) +
                          (2*NUM_ROUNDS*32*sizeof(uint8_t));
    unsigned int len = 0;

    // len calculation depends on type of response which can only be figured by
    // looking at the cHash together with the sig->ch[r]
    for (r = 0; r < NUM_ROUNDS; r++){
        int i = r/8;
        int j = r%8;

        bit[r] = cHash[i] & (1 << j) ? 1 : 0;  //challenge bit
        if (bit[r] == 0 && *sig->ch[r] == 0){
            len += obytes;
        }
        else if (bit[r] == 0 && *sig->ch[r] == 1){
            len += sizeof(point_proj);
        }
        else if (bit[r] != 0 && *sig->ch[r] == 0){
            len += sizeof(point_proj);
        }
        else if (bit[r] != 0 && *sig->ch[r] == 1){
            len += obytes;
        }
        else{
            printf("cannot calculate len of rest signature because of invalid"
                    "combination of bit=%d and *sig->ch[r]=%d\n",
                    bit[r], *sig->ch[r]);
            return -1;
        }
    }

    buf = calloc(1, len);
    memcpy(buf, sig_binary + offset, len);

    int act_resp_pos = 0;
    for (r = 0; r < NUM_ROUNDS; r++){
        if (bit[r] == 0 && *sig->ch[r] == 0){
            sig->resp[r] = calloc(1, obytes);
            memcpy(sig->resp[r], buf + act_resp_pos, obytes);
            act_resp_pos += obytes;
        }
        else if (bit[r] == 0 && *sig->ch[r] == 1){
            sig->resp[r] = calloc(1, sizeof(point_proj));
            memcpy(sig->resp[r], buf + act_resp_pos, sizeof(point_proj));
            act_resp_pos += sizeof(point_proj);
        }
        else if (bit[r] != 0 && *sig->ch[r] == 0){
            sig->resp[r] = calloc(1, sizeof(point_proj));
            memcpy(sig->resp[r], buf + act_resp_pos, sizeof(point_proj));
            act_resp_pos += sizeof(point_proj);
        }
        else if (bit[r] != 0 && *sig->ch[r] == 1){
            sig->resp[r] = calloc(1, obytes);
            memcpy(sig->resp[r], buf + act_resp_pos, obytes);
            act_resp_pos += obytes;
        }
        else{
            printf("wrong combination of bit[r]:%d and sig->ch[r]:%d\n"
                    "cannot reassemble responses\n", bit[r], *sig->ch[r]);
            return -1;
        }
    }

    free(buf);
    return 0;
}

int
parse_pubkey(unsigned char *PublicKey, int pub_len)
{
    int i, j;
    FILE *priv_fd, *pub_fd;
    char *line;
    size_t n = 0;
    ssize_t read;
    char * ptr;


    if ((pub_fd=fopen("public.key", "r")) == NULL){
        perror("failed to open public.key");
    }

    i = 0;
    while ((read = getline(&line, &n, pub_fd)) != -1){
        switch (i){
            case 0:
                if (strncmp(line, "-----BEGIN SISIG PUBLIC KEY-----", 32) != 0){
                    perror("invalid public.key format");
                    return -1;
                }
                break;
            case 1:
                if (read != 2 * pub_len + 1){
                    perror("public key too short");
                    return -1;
                }
                ptr = line;
                for (j = 0; j < pub_len; j++){
                    sscanf(ptr, "%2hhx", &PublicKey[j]);
                    ptr += 2;
                }
                break;
            case 2:
                if (strncmp(line, "-----END SISIG PUBLIC KEY-----", 30) != 0){
                    perror("invalid public.key format");
                    return -1;
                }
                break;
            default:
                perror("why do we read more than 3 lines?");
                return -1;
                break;
        }
        i += 1;
    }
    fclose(pub_fd);
    free(line);
    return 0;

}

int
SISig_P751_Verify(char *msg, struct SigData *sigdata,
       unsigned char *PublicKey)
{
    struct Signature *sig = calloc(1, sizeof(struct Signature));

    //read signature data without resp as we have to calculate length of resp
    //first with content from signature data
    //int siglen_cut = (2*NUM_ROUNDS*2*PBYTES) + (NUM_ROUNDS*sizeof(uint8_t)) +
    //    (2*NUM_ROUNDS*32*sizeof(uint8_t));
    //unsigned char *sig_cut_serialized = calloc(1, siglen_cut);
    //memcpy(sig_cut_serialized, sig_binary, siglen_cut);

    uint8_t *cHash;
    int cHashLength = NUM_ROUNDS/8;
    cHash = calloc(1, cHashLength);
    if ((gen_chash(sigdata->sig, sig, PBYTES, PublicKey, msg, cHash,
                    cHashLength)) != 0){
        printf("%s: failed to generate hash from sig_cut_serialized", __func__);
        return -1;
    }
    //free(sig_cut_serialized);

    uint8_t *bit = calloc(NUM_ROUNDS, sizeof(uint8_t));
    if (parse_sig_rest(sig, sigdata->sig, PBYTES, OBYTES, cHash, bit)
            != 0){
        printf("%s: failed to parse rest of signature", __func__);
        return -1;
    }

    if(isogeny_verify(&CurveIsogeny_SIDHp751, PublicKey, sig, bit) != 0)
        return -1;

    free(bit);
    free(cHash);

    int r;
    for(r=0; r<NUM_ROUNDS; r++)
    {
        free(sig->com[r][0]);
        free(sig->com[r][1]);
        free(sig->ch[r]);
        free(sig->h[r][0]);
        free(sig->h[r][1]);
        free(sig->resp[r]);
    }
    free(sig);

    return 0;
}
