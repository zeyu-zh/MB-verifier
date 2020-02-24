#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <memory.h>
#include <stdint.h>
#include <vector>
#include <fstream>
#include <time.h>
#include <iostream>
#include <iomanip>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <pwd.h>
using namespace std;

/* OCall functions */
void ocall_print_string(const char *str) {
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}
    
vector<string> strings;
void ocall_get_lines(const char *path, unsigned int* num_lines, uint64_t* pointer){
    std::ifstream inFile(path);
    string line;
    
    if (!inFile.good()) {
        printf("Cannot open file %s\n", path);
        exit(1);
    } else {
        while (std::getline(inFile, line)) {
            if (!line.empty())
                strings.push_back(line);
        }
        char** pstrings = (char**)malloc(strings.size() * sizeof(char*));
        for(uint32_t i = 0; i < strings.size(); i++)
            pstrings[i] = const_cast<char*>(strings[i].c_str());
        
        *pointer = (uint64_t)pstrings;
        *num_lines = strings.size();
    }
}


void ocall_destory_lines(uint64_t pointer){
    free((char**)pointer);
    for(vector<string>::iterator iter = strings.begin(); iter!= strings.end(); iter = strings.erase(iter));
    return;
}

void ocall_exit(int code){
    printf("Application exit due to a null pointer\n");
    exit(code);
}

void ocall_gettime(char* timeNow){
    struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
    memcpy(timeNow, &time, sizeof(time));
}

uint64_t ocall_mmap_pcap(const char *path, uint64_t* pointer){
    struct stat sk;
    
    /* map this file to memory */
    int fd = open(path, O_RDWR, 0644);
    if(fd == -1){
        cout << "Failed to open file " << path << endl;
        return -1;
    }
    stat(path, &sk);
    uint8_t* p_pcap = (uint8_t*)mmap(NULL, sk.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(p_pcap == nullptr){
        cout << "Failed to mmap file " << path << endl;
        return -1;
    }
    *pointer = (uint64_t)p_pcap;
    close(fd);

    return sk.st_size;
}


void ocall_munmap_pcap(uint32_t length, void* p_pcap){
    if(p_pcap != NULL)
        munmap(p_pcap, length);
}



unsigned long ocall_open_file(char* name) { return (unsigned long)fopen(name, "w+"); }
void ocall_write(unsigned long fd, char* id_and_hmac) { fputs(id_and_hmac, (FILE*)fd); }
void ocall_close(unsigned long fd) { fclose((FILE*)fd); }


void ocall_getchar(){ getchar(); }


