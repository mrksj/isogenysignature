#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#if (OS_TARGET != OS_BSD)
#include <malloc.h>
#endif

#include "test_extras.h"
#include "../SIDH.h"
#include "../SISig.h"

#define MSGSIZE 1024

struct Signature
{
    unsigned char *com[NUM_ROUNDS][2];      //2*NUM_ROUNDS*2*pbytes
    //only store ch_i,0 as ch_i,1 is always the opposite
    uint8_t *ch[NUM_ROUNDS];                    //NUM_ROUNDS*sizeof(int)
    unsigned char *h[NUM_ROUNDS][2];        //2*NUM_ROUNDS*32*sizeof(uint8_t)
    unsigned char *resp[NUM_ROUNDS];        //*resplen
};

int NUM_THREADS;
int
main(int argc, char **argv)
{
    int NUM = 1;
    int i;
    srand(time(0));
    struct timeval t0, t1, dt_keygen, dt_sign, dt_verify;
    struct timeval keygen_sum, sign_sum, verify_sum;
    struct timeval tmp;
    uint64_t keygen, sign, verify;
    timerclear(&keygen_sum);
    timerclear(&sign_sum);
    timerclear(&verify_sum);
    
    
    NUM_THREADS = 1;
    printf("NUM_THREADS: %d\n", NUM_THREADS);

    // Allocate space for keys
    unsigned char *PrivateKey = calloc(1, PRIV_KEY_LEN);
    unsigned char *PublicKey = calloc(1, PUB_KEY_LEN);
    unsigned char *PrivateKey2;
    unsigned char *PublicKey2;
    //unsigned char *PrivateKey2 = calloc(1, PRIV_KEY_LEN);
    //unsigned char *PublicKey2 = calloc(1, PUB_KEY_LEN);
    struct SigData *sigdata;


    char *sig_msg = calloc(1, MSGSIZE);        // msg to be signed
    strncpy(sig_msg, "Hi Bobby!", MSGSIZE-1);
    char *verify_msg = calloc(1, MSGSIZE);     // msg to be verified
    strncpy(verify_msg, "Hi Bobby!", MSGSIZE-1);

    for (i = 0; i < NUM; i++){
        //printf("Keygeneration...\n");
        gettimeofday(&t0, NULL);
        if(SISig_P751_Keygen(PrivateKey, PublicKey) != 0)
            goto cleanup;
        gettimeofday(&t1, NULL);
        timersub(&t1, &t0, &dt_keygen);
        tmp = keygen_sum;
        timeradd(&dt_keygen, &tmp, &keygen_sum);
        //printf("generated PrivateKey:\n");
        //print_hash(PrivateKey, PRIV_KEY_LEN);
        //printf("generated PublicKey:\n");
        //print_hash(PublicKey, PUB_KEY_LEN);

        //write keys to file and read back in to check functionality

        SISig_P751_Write_Privkey(PrivateKey, "private.key");
        SISig_P751_Write_Pubkey(PublicKey, "public.key");
        PrivateKey2 = SISig_P751_Read_Privkey("private.key");
        PublicKey2 = SISig_P751_Read_Pubkey("public.key");

        //printf("Signing...\n");
        gettimeofday(&t0, NULL);
        if((sigdata = SISig_P751_Sign(sig_msg, PrivateKey2, PublicKey2))
                == NULL)
            goto cleanup;
        gettimeofday(&t1, NULL);
        timersub(&t1, &t0, &dt_sign);
        tmp = sign_sum;
        timeradd(&dt_sign, &tmp, &sign_sum);

        //printf("siglen: %d\n", sigdata->siglen);
        //int i;
        //for(i = 0; i < sigdata->siglen; i++){
        //    printf("%02x", sigdata->sig[i]);
        //}
        //printf("\n");

        //printf("Verifying...\n");
        gettimeofday(&t0, NULL);
        if(SISig_P751_Verify(verify_msg, sigdata, PublicKey2) != 0)
            goto cleanup;
        gettimeofday(&t1, NULL);
        timersub(&t1, &t0, &dt_verify);
        tmp = verify_sum;
        timeradd(&dt_verify, &tmp, &verify_sum);

        printf("%d: %ld.%06ld,%ld.%06ld,%ld.%06ld\n", i, dt_keygen.tv_sec, dt_keygen.tv_usec, dt_sign.tv_sec, dt_sign.tv_usec, dt_verify.tv_sec, dt_verify.tv_usec);
    }

    keygen = (keygen_sum.tv_sec*1000000 + keygen_sum.tv_usec) / NUM;
    sign = (sign_sum.tv_sec * 1000000 + sign_sum.tv_usec) / NUM;
    verify = (verify_sum.tv_sec * 1000000 + verify_sum.tv_usec) / NUM;
    keygen_sum.tv_sec = keygen / 1000000;
    keygen_sum.tv_usec = keygen % 1000000;
    sign_sum.tv_sec = sign / 1000000;
    sign_sum.tv_usec = sign % 1000000;
    verify_sum.tv_sec = verify / 1000000;
    verify_sum.tv_usec = verify % 1000000;
    printf("***Mittelwerte:\n");
        printf("%d: %ld.%06ld,%ld.%06ld,%ld.%06ld\n", i, keygen_sum.tv_sec, keygen_sum.tv_usec, sign_sum.tv_sec, sign_sum.tv_usec, verify_sum.tv_sec, verify_sum.tv_usec);

cleanup:
    // Cleanup
    clear_words((void *) PrivateKey, NBYTES_TO_NWORDS(PRIV_KEY_LEN));
    clear_words((void *) PublicKey, NBYTES_TO_NWORDS(PUB_KEY_LEN));
    clear_words((void *) PrivateKey2, NBYTES_TO_NWORDS(PRIV_KEY_LEN));
    clear_words((void *) PublicKey2, NBYTES_TO_NWORDS(PUB_KEY_LEN));

    free(PrivateKey);
    free(PublicKey);
    free(PrivateKey2);
    free(PublicKey2);
    free(sig_msg);
    free(verify_msg);
    free(sigdata->sig);
    free(sigdata);

    return 0;
}
