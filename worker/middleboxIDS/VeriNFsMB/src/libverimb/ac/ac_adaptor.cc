#include "ac_adaptor.h"
#include <fstream>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "../base64/base64.h"
ACAdaptor::ACAdaptor()
{

}

ACAdaptor::~ACAdaptor()
{

}

void ACAdaptor::init(const PatternSet& patterns)
{
    int numPtrn = patterns.size();
    static std::string str;
    for (int i = 0; i < numPtrn; ++i) {
        str.assign((char *)patterns[i].data(), patterns[i].size());
        ac.insert(str);
    }
    //ac.outputTOP1();
}

void ACAdaptor::process(uint16_t id, const unsigned char* payload, int length, std::string& ringer)
{
    static std::string str;
    str.assign((char *)payload, length);
    
    ac.parse_text(str, id, ringer);
}

void ACAdaptor::process(uint16_t id, const unsigned char* payload, int length, std::vector<int>& node)
{
    //click_chatter("giaogiaogiao");
    static std::string str;
    str.assign((char *)payload, length);
    //click_chatter("giaogiaogiaogiao");
    ac.parse_text(str, id, node);
}



void ACAdaptor::read_nodeHMAC(const char* file) {
    ac.read_nodeHMAC(file);
}