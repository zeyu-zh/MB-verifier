#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdio.h>
#include <sstream>
#include <set>
using namespace std;

char cap_hex_to_byte(const std::string & hex) {
    // first half
    char byte = (hex[0] >= '0' && hex[0] <= '9') ? (hex[0] - '0') : (hex[0] - 'A' + 10); // small letters assumed
    byte *= 16;
    // second half
    byte += (hex[1] >= '0' && hex[1] <= '9') ? (hex[1] - '0') : (hex[1] - 'A' + 10);
    return byte;
}


vector<char> ptrn_str_to_bytes(const std::string & str) {
    vector<char> bytes;

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

int main(int argc, char *argv[]){
    if(argc < 2){
        cout << "Usage: ./generate_rules <input snort rules>" << endl;
        return 0;
    }

    ifstream input(argv[1]);
    set<string> patterns;
    string str;
    int max = 0;

    if(input.is_open()){    
        while (!input.eof()) {
            getline(input, str);
            size_t start_pos = 0, end_pos;
            while ((start_pos = str.find("content:\"")) != string::npos) {
               start_pos = str.find("content:\"");
               if(start_pos != string::npos){
                    str = str.substr(start_pos+9, str.length()-start_pos-9);
                    end_pos = str.find("\"");
                    string sub_str = str.substr(0, end_pos);
                    auto result = ptrn_str_to_bytes(sub_str);
                    if(result.size() > 4){
                        patterns.insert(sub_str);
                        if(result.size() > max)
                            max = result.size();
                    }
                        
               }
            }
        }
        
        ofstream output(string("snort_") + std::to_string(patterns.size()) + string(".pat"));
        for(auto str: patterns)
            output << str << endl;

        cout << max << endl;
        input.close();
        output.close();
    } else 
        cout << "Cannot open file " << string(argv[1]) << endl;
    

    return 0;
}