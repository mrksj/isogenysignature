#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
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

int
main(int argc, char **argv)
{
    int NUM_THREADS = 1;
    int i;
    clock_t t;
    clock_t total_keygen=0, total_sign=0, total_verify=0;
    double t_keygen, t_sign, t_verify;
    double total_t_keygen, total_t_sign, total_t_verify;
    printf("NUM_THREADS: %d\n", NUM_THREADS);
    srand(time(0));

    // Allocate space for keys
    unsigned char *PrivateKey = calloc(1, PRIV_KEY_LEN);
    unsigned char *PublicKey = calloc(1, PUB_KEY_LEN);
    unsigned char *PrivateKey2 = calloc(1, PRIV_KEY_LEN);
    unsigned char *PublicKey2 = calloc(1, PUB_KEY_LEN);
    struct SigData *sigdata;


    char *sig_msg = calloc(1, MSGSIZE);        // msg to be signed
    strncpy(sig_msg, "Hi Bobby!", MSGSIZE-1);
    char *verify_msg = calloc(1, MSGSIZE);     // msg to be verified
    strncpy(verify_msg, "Hi Bobby!", MSGSIZE-1);

    for (i = 0; i < 100; i++){
        printf("Keygeneration...\n");
        t = clock();
        if(SISig_P751_Keygen(PrivateKey, PublicKey) != 0)
            goto cleanup;
        t = clock() - t;
        t_keygen = ((double)t)/CLOCKS_PER_SEC;
        total_keygen += t;
        printf("generated PrivateKey:\n");
        print_hash(PrivateKey, PRIV_KEY_LEN);
        printf("generated PublicKey:\n");
        print_hash(PublicKey, PUB_KEY_LEN);

        //write keys to file and read back in to check functionality

        SISig_P751_Write_Privkey(PrivateKey, "private.key");
        SISig_P751_Write_Pubkey(PublicKey, "public.key");
        PrivateKey2 = SISig_P751_Read_Privkey("private.key");
        PublicKey2 = SISig_P751_Read_Pubkey("public.key");

        printf("Signing...\n");
        t = clock();
        if((sigdata = SISig_P751_Sign(sig_msg, PrivateKey2, PublicKey2))
                == NULL)
            goto cleanup;
        t = clock() - t;
        t_sign = ((double)t)/CLOCKS_PER_SEC;
        total_sign += t;

        printf("siglen: %d\n", sigdata->siglen);
        //int i;
        //for(i = 0; i < sigdata->siglen; i++){
        //    printf("%02x", sigdata->sig[i]);
        //}
        //printf("\n");

        printf("Verifying...\n");
        t = clock();
        if(SISig_P751_Verify(verify_msg, sigdata, PublicKey2) != 0)
            goto cleanup;
        t = clock() - t;
        t_verify = ((double)t)/CLOCKS_PER_SEC;
        total_verify += t;

        printf("%f,%f,%f\n", t_keygen, t_sign, t_verify);
    }
    total_t_keygen = ((double)total_keygen) / (CLOCKS_PER_SEC * 100);
    total_t_sign = ((double)total_sign) / (CLOCKS_PER_SEC * 100);
    total_t_verify = ((double)total_verify) / (CLOCKS_PER_SEC * 100);

    printf("***Mittelwerte:\n");
    printf("%f,%f,%f\n", total_t_keygen, total_t_sign, total_t_verify);

cleanup:
    // Cleanup
    clear_words((void *) PrivateKey, NBYTES_TO_NWORDS(PRIV_KEY_LEN));
    clear_words((void *) PublicKey, NBYTES_TO_NWORDS(PUB_KEY_LEN));

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
