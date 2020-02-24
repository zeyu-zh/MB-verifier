#include "pattern_loader.h"

#include <stdlib.h>
#include <stdio.h>
#include "sgx_trts.h"
#include "Enclave_t.h"
#include "Enclave.h"
#include <stdint.h>
#include <string>
#include <string.h>
//#include <memory.h>

uint64_t inet_addr(char *ptr){
    int a[4],i = 0;
    uint64_t num;
    char *p1 = ptr, *p2, *p3;
    while(*p1 != '\0' && i < 4){
        p2 = strstr(p1,".");
        if(i != 3){
            p3 = p2+1;
            *p2 = '\0';
        }

        a[i] = atoi(p1);
        if(a[i] < 0 || a[i] > 255){
            ocall_printf("Invalid IP address!\n");
            ocall_exit(1);    
        }
        p1 = p3;
        i++;
    }
        num = a[0] * 256 * 256 * 256 + a[1] * 256 * 256 + a[2] * 256 + a[3];
        return num;
}


// should call ocall_destory_lines(uint64_t pointer) after load_pattern
uint64_t PatternLoader::load_pattern_file(const char* file, PatternSet& ptnSet) {
	uint32_t nums;
	uint64_t lines;
	ocall_get_lines(file, &nums, &lines);
	char** plines = (char**)lines;

	for(int i = 0; i < nums; i++){
		std::string line(plines[i]);
		// test code
		//ocall_printf("%s\n", line.c_str());
		ptnSet.push_back(ptrn_str_to_bytes(line));
	}
	return lines;
}
// should call ocall_destory_lines(uint64_t pointer) after load_pattern
uint64_t PatternLoader::load_firewall_file(const char * file, std::vector<fwRule>& ruleSet)
{
	uint32_t nums;
	uint64_t lines;
	ocall_get_lines((char*)file, &nums, &lines);
	char** plines = (char**)lines;
	fwRule rule;

	for(uint32_t i = 0; i < nums; i++){
		std::string line(plines[i]);
		// test code
		//ocall_printf("%s\n", line.c_str());
		if(rule_str_to_rule(line, rule))
	 		ruleSet.push_back(rule);
	}
	return lines;
}

char PatternLoader::cap_hex_to_byte(const std::string & hex) {
    // first half
    char byte = (hex[0] >= '0' && hex[0] <= '9') ? (hex[0] - '0') : (hex[0] - 'A' + 10); // small letters assumed
    byte *= 16;
    // second half
    byte += (hex[1] >= '0' && hex[1] <= '9') ? (hex[1] - '0') : (hex[1] - 'A' + 10);
    return byte;
}

bool PatternLoader::rule_str_to_rule(const std::string& str, fwRule& rule)
{
	static const char* const ruleHead = "block in log quick from ";
	static const char* const connectStr = "to ";
	static const char* const anyStr = "any";

	const char* cstr = str.data();
	if (str.length() < strlen(ruleHead) || memcmp(ruleHead, cstr, strlen(ruleHead)) != 0)
		return false;
	
	cstr += strlen(ruleHead);

	char* dstr = (char*)cstr;
	while (*(++dstr) != ' '&& *dstr != 0);
	*dstr = 0;
	const char* srcip = cstr;

	cstr = dstr+1;
	if (memcmp(cstr, connectStr, strlen(connectStr)) != 0)
		return false;
	
	cstr += strlen(connectStr);
	dstr = (char*)cstr;
	while (*(++dstr) != '\n'&& *dstr != ' '&& *dstr != '/'&& *dstr != 0);
	*dstr = 0;
	const char* dstip = cstr;

	if (memcmp(srcip, anyStr, strlen(anyStr)) == 0) {
		rule.isSrc = false;
		rule.ip = inet_addr((char*)dstip);
	}
	else {
		rule.isSrc = true;
		rule.ip = inet_addr((char*)srcip);
	}

	//if (memcmp(dstip, anyStr, strlen(anyStr)) == 0)
	//{
	//	rule.minDstIP = 0;
	//	rule.maxDstIP = 0xffffffff;
	//}
	//else
	//{
	//	rule.minDstIP = inet_addr(dstip);
	//	rule.maxDstIP = rule.minDstIP + 1;
	//	rule.minDstIP -= 1;
	//}

	return true;
}

Binary PatternLoader::ptrn_str_to_bytes(const std::string & str) {
    Binary bytes;

    size_t strlen = str.length();
    for (size_t i = 0; i < strlen; ) {
        // handle binary data in hex form
        if (str[i] == '|') {
            // find next '|' and extract the hex string
            size_t nextDelim = str.find('|', i + 1);
            const std::string& hexes = str.substr(i + 1, nextDelim - i - 1);

            // transform each char
            size_t idx = 0;
            while (idx < hexes.length()) {
                if (hexes[idx] == ' ') {
                    ++idx;
                    continue;
                }
                bytes.push_back(cap_hex_to_byte(hexes.substr(idx, 2)));
                idx += 2;
            }

            // update index
            i = nextDelim + 1;
        } else { // normal character
            bytes.push_back(str[i]);
            ++i;
        }
    }
    return bytes;
}
