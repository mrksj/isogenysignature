/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key 
*       exchange providing 128 bits of quantum security and 192 bits of classical security.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: utility header file for tests
*
*********************************************************************************************/  

#ifndef __TEST_EXTRAS_H__
#define __TEST_EXTRAS_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif

    
#include "../SIDH_internal.h"
#include "../keccak.h"

#define NUM_ROUNDS       248
#define MSG_LEN          1024
extern int NUM_THREADS;

// Access system counter for benchmarking
int64_t cpucycles(void);

// Generate "nbytes" random bytes and output the result to random_array
CRYPTO_STATUS random_bytes_test(unsigned int nbytes, unsigned char* random_array);

// Comparing "nword" elements, a=b? : (1) a!=b, (0) a=b
int compare_words(digit_t* a, digit_t* b, unsigned int nwords);

// Generating a pseudo-random field element in [0, p751-1] 
void fprandom751_test(felm_t a);

// Generating a pseudo-random element in GF(p751^2)
void fp2random751_test(f2elm_t a);

// Comparing two field elements, a=b? : (1) a>b, (0) a=b, (-1) a<b
int fpcompare751(felm_t a, felm_t b);

// Comparing two quadratic extension field elements, ai=bi? : (1) ai!=bi, (0) ai=bi
int fp2compare751(f2elm_t a, f2elm_t b);

// Basic Montgomery multiplication, mc = ma*mb*R^-1 mod p751, where ma,mb,mc in [0, p751-1] and R = 2^768
void fpmul751_mont_basic(felm_t ma, felm_t mb, felm_t mc);

// Conversion to Montgomery representation
void to_mont_basic(felm_t a, felm_t mc);

// Conversion from Montgomery representation to standard representation
void from_mont_basic(felm_t ma, felm_t c);

void print_hash(unsigned char hash[], int size);

void
hashdata(unsigned char *PublicKey, char *msg, unsigned int pbytes,
    unsigned char* com[NUM_ROUNDS][2], uint8_t* ch[NUM_ROUNDS],
    uint8_t* HashResp[NUM_ROUNDS][2], int hlen, int dlen, uint8_t *data,
    uint8_t *cHash, int cHashLength);

#ifdef __cplusplus
}
#endif


#endif
