/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <cstdlib>
#include <string>
#include <limits>
#include <cmath>
//#include <sys/types.h>
//#include <string.h>
#include <stdio.h>
#include "sgx_trts.h"
#include "Enclave_t.h"
#include "Enclave.h"
#include "pattern_loader.h"
#include "ac/ac_adaptor.h"
#include "bloom.h"
#include "base64.h"
#include "sgx_tcrypto.h"
#include "pcap_parser.h"

using namespace std;


uint8_t g_sha256_key[16]; // 128 bits

uint8_t* get_key(void){
    uint8_t* p = (uint8_t*)malloc(16);
    memcpy(p, g_sha256_key, 16);
    return p;
}




PatternSet patterns;
ACAdaptor* engine;


int ocall_printf(const char* fmt, ...) {
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


void ecall_init_IDS(void){
    /* init key */
    //sgx_status_t ret = sgx_read_rand(g_sha256_key, 16);
    memset(g_sha256_key, 'a', 16);

    /* init ac trie*/
    PatternLoader::load_pattern_file("../../rules/etopen_26763.pat", patterns);
    engine = new ACAdaptor();
    engine->init(patterns);
    aho_corasick::state<char> state;
    state.get_all_states();

    /* parse pcap and verfiy */
    // VERI_DATA veri_data;
    // get_pcap_data("../../pcap/m58.pcap", &veri_data);
    // destory_pcap_data(&veri_data);
}


