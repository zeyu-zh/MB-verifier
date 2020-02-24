#ifndef _VERIFICATION_H_
#define _VERIFICATION_H_

#include <vector>
#include <map>
#include <set>
#include <string>
#include <utility>
#include "aho_corasick.h"



using namespace std;


class Verification {

    public:
    struct Node {
        unsigned long d_depth;//原节点深度
        map<char, int> d_success;//后继节点的字符以及下标
        int d_failure;//failure指针指向的节点下标
        set<pair<string, unsigned>> d_emits;//原节点上的pattern集合，pair<pattern, pattern序号>
        int d_num;//原节点的下标
        char bf[20];//原节点的bf字符串
        uint8_t auth[16];
    };

    struct PktInfo {
        vector<int> search_path;//pkt在ACtree遍历过程中按顺序经过的节点下标
        string payload;//pkt的payload
        set<string> pattern;//pkt匹配到的所有pattern
    };

    map<int, Node> nodes;//原节点下标d_num --> Node结构体
    map<int, PktInfo> pkt_search_info;//pktID --> PktInfo
    string merkle_tree_point[2048];//存储第二部分返回的merkle_tree的节点

    public:

    Verification();
    ~Verification();
    
    bool check_nodes_auth();
    bool check_pkt_search_path();
    bool check_pkt_bf();
    bool check_merkle_tree_point();
    string get_hash_value(int i);
};


#endif