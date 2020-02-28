// #include "veri_header.h"


// #include <clicknet/ether.h>
// #include <time.h>
// #include <arpa/inet.h>
// #include <net/if.h>
#include "pkt_reader.h"
#include "sgx_trts.h"
#include "Enclave_t.h"
#include "Enclave.h"
#include <sgx_tcrypto.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <veri_header.h>
using namespace std;

struct timespec{
    uint64_t tv_sec;
    uint64_t tv_nsec;
};

string encTools::SHA256(uint8_t* str, int len){
    sgx_sha256_hash_t digest;
    sgx_status_t ret = sgx_sha256_msg(str, len, &digest);
    if(ret != SGX_SUCCESS){
        ocall_printf("Failed to calculate sha256\n");
        ocall_exit(1);
        return nullptr;
    }
    string temp = "";
    for(int i = 0; i < 32; i++)
        temp += ((char*)digest)[i];

	return temp;
}

string encTools::SHA256(const string & data){
	uint8_t const* pbData = (uint8_t*)data.data();
	unsigned int nDataLen = data.size();
    
    sgx_sha256_hash_t digest;
    sgx_status_t ret = sgx_sha256_msg(pbData, nDataLen, &digest);
    if(ret != SGX_SUCCESS){
        ocall_printf("Failed to calculate sha256\n");
        ocall_exit(1);
        return nullptr;
    }
    string temp = "";
    for(int i = 0; i < 32; i++)
        temp += ((char*)digest)[i];

	return temp;
}

string encTools::timeNow(){
    char timeNow[16];
    ocall_gettime(timeNow);
	return string().append(timeNow, 16);
}

double encTools::differTimeInNsec(const char * const begin, const char * const end)
{
	timespec* b = (timespec*)begin, *e = (timespec*)end;
	return (e->tv_sec - b->tv_sec) * 1000000000 + (e->tv_nsec - b->tv_nsec);
}


