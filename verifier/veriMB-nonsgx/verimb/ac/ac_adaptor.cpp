#include "ac_adaptor.h"
#include <iostream>
using namespace std;

ACAdaptor::ACAdaptor()
{

}

ACAdaptor::~ACAdaptor()
{

}

void ACAdaptor::init(const PatternSet& patterns)
{
    //cout<<"ACAdaptor::init"<<endl;
    
    int numPtrn = (int)patterns.size();
    static std::string str;
    for (int i = 0; i < numPtrn; ++i) {
        str.assign((char *)patterns[i].data(), patterns[i].size());
        //cout<<"insert:"<<str<<endl;
        ac.insert(str);
    }
    ac.construct_failure_states();
    ac.construct_acc();
}

void ACAdaptor::process(uint16_t id, const unsigned char* payload, int length, std::string& ringer)
{
    static std::string str;
    str.assign((char *)payload, length);
    
    ac.parse_text(str, id, ringer);
}

aho_corasick::trie* ACAdaptor::get_ac_tree()
{
    return &ac;
}
