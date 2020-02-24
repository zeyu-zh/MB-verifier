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
    
    aho_corasick::trie* get_ac_tree();

private:
    aho_corasick::trie ac;
};

#endif
