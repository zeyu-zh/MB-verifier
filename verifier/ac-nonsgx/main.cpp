#include <iostream>
#include <chrono>
#include <string.h>
#include "pattern_loader.h"
#include "ac/ac_adaptor.h"

using namespace std;

PatternSet patterns;
ACAdaptor* engine;


string pattern_path = "../Rules/snort_10000.pat";

void print_patterns(PatternSet& ptns)
{
    for(int i=0; i < ptns.size(); i++)
    {
        for(int j = 0; j < ptns[i].size(); j++)
        {
            cout<<(char)ptns[i][j];
        }
        cout<<endl;
    }
}


int main(int argc, const char * argv[]) {
    

    auto start = std::chrono::high_resolution_clock::now();
    //setup阶段
    
    /*读入处理好后的pattern文件*/
    PatternLoader::load_pattern_file(pattern_path.data(), patterns);
    
    
    /*保存规则集id、规则数目meta和secret*/
    /*生成secret*/
    
    /*建AC树，AC树的结构保存在engine.ac中*/
    engine = new ACAdaptor();
    engine->init(patterns);
    
    /*计算每个节点的HMAC和每条规则的HMAC*/
    /*计算每条规则的auth_r*/
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Overhead: " << elapsed.count() << std::endl;
    
    
    return 0;
}
