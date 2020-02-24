#include "verification.h"
#include "bloom/bloom.h"  
#include "veri_header.h"
#include "sgx_tcrypto.h"
#include "Enclave.h"
#include "Enclave_t.h"

Verification::Verification(){}
Verification::~Verification(){}

bool Verification::check_nodes_auth(){
    string temp;
    uint8_t hmac[16];

    for(auto it = nodes.begin(); it != nodes.end(); ++it) {
        temp = "";
        const auto& a = it->second;
        temp += std::to_string(a.d_depth);
        for (auto i = a.d_success.begin(); i != a.d_success.end(); ++i) {
            temp += i->first;
            temp += std::to_string(i->second);
        }
	    temp += std::to_string(a.d_failure);
        for (auto i = a.d_emits.begin(); i != a.d_emits.end(); ++i) {
            temp += i->first;
            temp += std::to_string(i->second);
        }
        temp += std::to_string(a.d_num);
        for(int i = 0; i < 20; i++)
            temp += a.bf[i];
        
        /*以下代码执行需要SGX*/
		uint8_t* p_key = get_key();
        sgx_hmac_sha256_msg((const uint8_t*)temp.c_str(), temp.length(), p_key, 16, hmac, 16);
        if(0 != memcmp(hmac, a.auth, 16))
            return false;
    }

    return true;
}

bool Verification::check_pkt_search_path() {
    for(auto it = pkt_search_info.begin(); it != pkt_search_info.end(); ++it) {
        const auto& info = it -> second;
        int p = 0;
        int node_p = 0;
        while(p < info.payload.length()) {
            char temp_step = info.payload[p];
            int temp_node = info.search_path[node_p];

            while(true) {
                if(nodes[temp_node].d_success.find(temp_step) != nodes[temp_node].d_success.end())
                    break;
                
                if(node_p == info.search_path.size()-1)
                    return false;

                if(nodes[temp_node].d_failure != info.search_path[node_p+1])
                    return false;

                if(nodes[temp_node].d_failure == 0)
                    break;
                
                node_p ++;
                temp_node = info.search_path[node_p];
            }

            if(nodes[temp_node].d_success.find(temp_step) != nodes[temp_node].d_success.end()) {
                node_p++;
                if(node_p >= info.search_path.size())
                    return false;
                if(nodes[temp_node].d_success.find(temp_step)->second != info.search_path[node_p])
                    return false;
                p++;
                continue;
            }

            if(nodes[temp_node].d_failure == 0) {
                p++;
                node_p++;
            }
        }
    }

    return true;
}

bool Verification::check_pkt_bf(){
    for(auto it = pkt_search_info.begin(); it != pkt_search_info.end(); ++it){
        char bf[20];
        for( int i = 0; i < 20; i++)
            bf[i] = nodes[it->second.search_path[0]].bf[i];
        for(int i = 1; i < it->second.search_path.size(); i++)
            for(int j = 0; j < 20; j++)
                bf[j] |= nodes[it->second.search_path[i]].bf[j];
        Bloom temp_bloom;
        bloom_init(&temp_bloom, 32, 0.1);
        for(auto& i : it->second.pattern)
            bloom_add(&temp_bloom, i.c_str(), i.length());

        if(0 != memcmp(temp_bloom.buffer, bf, 20))
            return false;
    }

    return true;

}

bool Verification::check_merkle_tree_point(){
    string root_hash = get_hash_value(0);
    if(root_hash != merkle_tree_point[0])
        return false;
    return true;

}

string Verification::get_hash_value(int i){
    string str1 = merkle_tree_point[2*i+1];
    string str2 = merkle_tree_point[2*i+2];
    if(str1 == "")
        str1 = get_hash_value(2*i+1);
    if(str2 == "")
        str2 = get_hash_value(2*i+2);
    return encTools::SHA256(str1+str2);
}