#ifndef AC_ADPATOR_H
#define AC_ADPATOR_H

#include "../pm_adaptor.h"
#include "aho_corasick.h"

class ACAdaptor : public PMAdaptor
{
public:
    
    ACAdaptor();

    ~ACAdaptor(); 

    void init(const PatternSet& patterns);
  
    void process(uint16_t id, const unsigned char* payload, int length, std::string& ringer);

    std::string process(uint16_t id, const unsigned char* payload, int length, std::vector<int>& node);

    void read_nodeHMAC(const char* file);

public:
    aho_corasick::trie ac;
};

#endif