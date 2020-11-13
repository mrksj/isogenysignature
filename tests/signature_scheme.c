#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#if (OS_TARGET != OS_BSD)
#include <malloc.h>
#endif

#include "test_extras.h"
#include "../SIDH.h"
#include "../SISig.h"

#define MSGSIZE 1024

int
main(int argc, char **argv)
{
    int NUM_THREADS = 1;
    printf("NUM_THREADS: %d\n", NUM_THREADS);
    srand(time(0));

    // Allocate space for keys
    unsigned char *PrivateKey, *PublicKey;
    PrivateKey = calloc(1, PRIV_KEY_LEN);
    PublicKey = calloc(1, PUB_KEY_LEN);

    char *sig_msg = calloc(1, MSGSIZE);        // msg to be signed
    char *verify_msg = calloc(1, MSGSIZE);     // msg to be verified

    unsigned char *signature;


    if(SISig_P751_Keygen(PrivateKey, PublicKey) != 0)
        goto cleanup;

    if(SISig_P751_Sign(sig_msg, signature, PrivateKey, PublicKey) != 0)
        goto cleanup;

    if(SISig_P751_Verify(verify_msg, signature, PublicKey) != 0)
        goto cleanup;

cleanup:
    // Cleanup
    clear_words((void *) PrivateKey, NBYTES_TO_NWORDS(PRIV_KEY_LEN));
    clear_words((void *) PublicKey, NBYTES_TO_NWORDS(PUB_KEY_LEN));

    free(PrivateKey);
    free(PublicKey);
    free(sig_msg);
    free(verify_msg);
    free(signature);

    return 0;
}

//// Optional parameters: #threads, #rounds
//int main(int argc, char *argv[])
//{
//    NUM_THREADS = 1;
//
//    if (argc > 1) {
//        NUM_THREADS = atoi(argv[1]);
//    }
//
//    printf("NUM_THREADS: %d\n", NUM_THREADS);
//
//    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
//
//    unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7)/8;      // Number of bytes in a field element
//    unsigned int n, obytes = (CurveIsogeny_SIDHp751.owordbits + 7)/8;   // Number of bytes in an element in [1, order]
//    unsigned long long cycles1, cycles2, scycles;
//    int priv_fd, pub_fd;
//    unsigned int *resplen = calloc(1, sizeof(unsigned int));
//
//    // Allocate space for keys
//    unsigned char *PrivateKey, *PublicKey;
//    PrivateKey = (unsigned char*)calloc(1, obytes);        // One element in [1, order]
//    PublicKey = (unsigned char*)calloc(1, 4*2*pbytes);     // Four elements in GF(p^2)
//
//    struct Signature sig;
//    struct Responses resp;
//
//    // msg XXX: read from file or as commandlineparameter
//    char *msg;
//    msg = calloc(1, MSG_LEN);
//    strncpy(msg, "Hi Bob!", MSG_LEN-1);
//
//    if (parse_keys(PrivateKey, PublicKey, obytes, 4 * 2 * pbytes) != 0){
//        printf("failed to parse keys\n");
//        return -1;
//    }
//    
//    // compute signature
//    cycles1 = cpucycles();
//    Status = isogeny_sign(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey, &sig, msg, &resp, resplen);
//    if (Status != CRYPTO_SUCCESS) {
//        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
//        return EXIT_FAILURE;
//    }
//    cycles2 = cpucycles();
//    scycles = cycles2 - cycles1;
//
//    printf("Signing ............ %10lld cycles\n", scycles);
//
//    // write signature to file
//    if ((write_sigfile(sig, pbytes, obytes, resp, *resplen)) != 0){
//        perror("Could not write signature to file");
//    }
//    printf("resplen: %d\n", *resplen);
//
//
//    clear_words((void*)PrivateKey, NBYTES_TO_NWORDS(obytes));
//    clear_words((void*)PublicKey, NBYTES_TO_NWORDS(4*2*pbytes));
//
//    free(PrivateKey);
//    free(PublicKey);
//    free(msg);
//    free(resplen);
//
//
//    return 0;
//}


//// Optional parameters: #threads, #rounds
//int main(int argc, char *argv[])
//{
//    NUM_THREADS = 1;
//
//    if (argc > 1) {
//        NUM_THREADS = atoi(argv[1]);
//    }
//
//    printf("NUM_THREADS: %d\n", NUM_THREADS);
//
//    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
//
//    // Number of bytes in a field element
//    unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7)/8;
//    // Number of bytes in an element in [1, order]
//    unsigned int n, obytes = (CurveIsogeny_SIDHp751.owordbits + 7)/8;
//    unsigned long long cycles1, cycles2, vcycles;
//    int pub_fd, sig_fd;
//
//    // Allocate space for public key
//    unsigned char *PublicKey;
//    PublicKey = (unsigned char*)calloc(1, 4*2*pbytes); // 4 elements in GF(p^2)
//
//    struct Signature sig;
//
//    // msg XXX: read from file or as commandlineparameter
//    char *msg;
//    msg = calloc(1, MSG_LEN);
//    strncpy(msg, "Hi Bob!", MSG_LEN-1);
//
//    if (parse_pubkey(PublicKey, 4 * 2 * pbytes) != 0){
//        perror("failed to read PublicKey");
//        return -1;
//    }
//
//    //read signature data without resp as we have to calculate length of resp
//    //first with content from signature data
//    int siglen_cut = (2*NUM_ROUNDS*2*pbytes) + (NUM_ROUNDS*sizeof(uint8_t)) +
//        (2*NUM_ROUNDS*32*sizeof(uint8_t));
//    unsigned char *sig_cut_serialized = calloc(1, siglen_cut);
//    if ((read_sigfile_cut(siglen_cut, sig_cut_serialized)) != 0)
//    {
//        perror("Could not read signature data from signature file");
//        return -1;
//    }
//
//    uint8_t *cHash;
//    int cHashLength = NUM_ROUNDS/8;
//    cHash = calloc(1, cHashLength);
//    if ((gen_chash(sig_cut_serialized, &sig, pbytes, PublicKey, msg, cHash,
//                    cHashLength)) != 0){
//        perror("Could not generate ChallengeHash J_i || ... || J_2lambda");
//    }
//    free(sig_cut_serialized);
//
//    uint8_t *bit = calloc(NUM_ROUNDS, sizeof(uint8_t));
//    if ((parse_sigfile_rest(&sig, pbytes, obytes, cHash, bit)) != 0){
//        perror("Could not parse rest of sigfile");
//    }
//
//    cycles1 = cpucycles();
//    Status = isogeny_verify(&CurveIsogeny_SIDHp751, PublicKey, &sig, bit);
//    if (Status != CRYPTO_SUCCESS) {
//        printf("\n\n   Error detected: %s \n\n",
//            SIDH_get_error_message(Status));
//        return false;
//    }
//    cycles2 = cpucycles();
//    vcycles = cycles2 - cycles1;
//
//    printf("Verifying .......... %10lld cycles\n\n", vcycles);
//
//
//    clear_words((void*)PublicKey, NBYTES_TO_NWORDS(4*2*pbytes));
//
//    free(PublicKey);
//    free(msg);
//    free(bit);
//    free(cHash);
//
//    int r;
//    for(r=0; r<NUM_ROUNDS; r++)
//    {
//        free(sig.com[r][0]);
//        free(sig.com[r][1]);
//        free(sig.ch[r]);
//        free(sig.h[r][0]);
//        free(sig.h[r][1]);
//        free(sig.resp[r]);
//    }
//
//    return 0;
//}
