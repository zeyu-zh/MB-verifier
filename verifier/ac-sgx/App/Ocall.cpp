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

using namespace std;

/* OCall functions */
void ocall_print_string(const char *str)
{
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
    exit(1);
}

void ocall_gettime(char* timeNow){
    struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
    memcpy(timeNow, &time, sizeof(time));
}