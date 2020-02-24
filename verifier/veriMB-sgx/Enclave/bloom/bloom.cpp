/*
 *  Copyright (c) 2012-2019, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

/*
 * Refer to bloom.h for documentation on the public interfaces.
 */

#include <assert.h>
//#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/stat.h>
//#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "bloom.h"
#include "murmurhash.h"
#include "Enclave.h"
#define MAKESTRING(n) STRING(n)
#define STRING(n) #n


inline static int test_bit_set_bit(unsigned char * buf, unsigned int x, int set_bit) {
    unsigned int byte = x >> 3;
    unsigned char c = buf[byte];        // expensive memory access
    unsigned int mask = 1 << (x % 8);

    if (c & mask)
        return 1;
    else if (set_bit)
        buf[byte] = c | mask;

    return 0;
}


static int bloom_check_add(Bloom * bloom, const void * buffer, int len, int add) {
    if (bloom->ready == 0) {
        ocall_printf("bloom at %p not initialized!\n", (void *)bloom);
        return -1;
    }

    int hits = 0;
    register uint32_t a = murmurhash(buffer, len, 0x9747b28c);
    register uint32_t b = murmurhash(buffer, len, a);
    register uint32_t x;
    register uint32_t i;

    for (i = 0; i < bloom->hashes; i++) {
        x = (a + i*b) % bloom->bits;
        if (test_bit_set_bit(bloom->bf, x, add))
            hits++;
        else if (!add) // Don't care about the presence of all the bits. Just our own.
            return 0;
    }

    if (hits == bloom->hashes)
        return 1;                // 1 == element already in (or collision)

  return 0;
}


int bloom_init_size(Bloom * bloom, int entries, double error, unsigned int cache_size){ return bloom_init(bloom, entries, error); }


int bloom_init(Bloom * bloom, int entries, double error) {
    bloom->ready = 0;

    if (entries < 16 || error == 0) return 1;

    bloom->entries = entries;
    bloom->error = error;

    double num = log(bloom->error);
    double denom = 0.480453013918201; // ln(2)^2
    bloom->bpe = -(num / denom);

    double dentries = (double)entries;
    bloom->bits = (int)(dentries * bloom->bpe);

    if (bloom->bits % 8)
        bloom->bytes = (bloom->bits / 8) + 1;
    else 
        bloom->bytes = bloom->bits / 8;

    bloom->hashes = (int)ceil(0.693147180559945 * bloom->bpe);  // ln(2)
    //bloom->bytes = 20;
    //bloom->bf = (unsigned char *)calloc(bloom->bytes, sizeof(unsigned char));
    if (bloom->bf == NULL)   // LCOV_EXCL_START
        return 1;            // LCOV_EXCL_STOP

    bloom->ready = 1;
    return 0;
}


int bloom_check(Bloom * bloom, const void * buffer, int len) { return bloom_check_add(bloom, buffer, len, 0); }


int bloom_add(Bloom * bloom, const void * buffer, int len) { return bloom_check_add(bloom, buffer, len, 1); }


void bloom_print(Bloom * bloom) {
    ocall_printf("bloom at %p\n", (void *)bloom);
    ocall_printf(" ->entries = %d\n", bloom->entries);
    ocall_printf(" ->error = %f\n", bloom->error);
    ocall_printf(" ->bits = %d\n", bloom->bits);
    ocall_printf(" ->bits per elem = %f\n", bloom->bpe);
    ocall_printf(" ->bytes = %d\n", bloom->bytes);
    ocall_printf(" ->hash functions = %d\n", bloom->hashes);
}


void bloom_free(Bloom * bloom) {
    if (bloom->ready)
        //free(bloom->bf);
    bloom->ready = 0;
}


int bloom_reset(Bloom * bloom) {
    if (!bloom->ready) return 1;
    memset(bloom->bf, 0, bloom->bytes);
    return 0;
}

const char * bloom_version() { return MAKESTRING(BLOOM_VERSION); }



// void bloom_sample_usage(){
//     Bloom bloom;
//     char* str = "Happy Chinese New Year!";
    
//     bloom_init(&bloom, 2000, 0.01);
//     bloom_add(&bloom, str, sizeof(str));

//     if(bloom_check(&bloom, str, sizeof(str)))
//         ocall_printf("Bloom test: It may be here!\n");

//     bloom_free(&bloom);
// }