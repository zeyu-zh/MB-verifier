#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdio.h>
#include <sstream>
using namespace std;

int main(int argc, char *argv[]){
    if(argc < 2){
        cout << "Usage: ./generate_rules <input snort rules>" << endl;
        return 0;
    }

    ifstream input(argv[1]);
    vector<string> patterns;
    string str;

    if(input.is_open()){    
        while (!input.eof()) {
            getline(input, str);
            size_t start_pos = 0, end_pos;
            while ((start_pos = str.find("content:\"")) != string::npos) {
            //    start_pos = str.find("content:\"");
            //    if(start_pos != string::npos){
                    str = str.substr(start_pos+9, str.length()-start_pos-9);
                    end_pos = str.find("\"");
                    patterns.push_back(str.substr(0, end_pos));
            //    }
            }
        }
        
        ofstream output(string("snort_") + std::to_string(patterns.size()) + string(".pat"));
        for(auto str: patterns)
            output << str << endl;

        input.close();
        output.close();
    } else 
        cout << "Cannot open file " << string(argv[1]) << endl;
    

    return 0;
}