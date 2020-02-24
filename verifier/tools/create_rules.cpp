#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdio.h>
#include <sstream>
#include <random>
using namespace std;

char table[] = {
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P',\
    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'z', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Z',\
    'x', 'c', 'v', 'b', 'n', 'm', '1', '2', '3', '4', 'X', 'C', 'V', '5', '6', '7', '8', '9', '0', '~',\
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '=', '{', '}', ':', ';', ',', '<', '.',\
    '>', '?'};

int num[] = {5000, 10000, 15000};
int main(int argc, char *argv[]){
    string file1("../Rules/snort_5000.pat");
    string file2("../Rules/snort_10000.pat");
    string file3("../Rules/snort_15000.pat");
    
    ofstream output1(file1.c_str());
    ofstream output2(file2.c_str());
    ofstream output3(file3.c_str());

    default_random_engine generator;
    uniform_int_distribution<int> distribution(0, sizeof(table)-1);
    uniform_int_distribution<int> pat_len(0, sizeof(table)-1);
    int dice_roll;

    for(int k = 0; k < sizeof(num) / 4; k++){
        for(int i = 0; i < num[k]; ){
            dice_roll = pat_len(generator);
            if(dice_roll < 3)
                continue;
            else {
                string str;
                for(int j = 0; j < dice_roll; j++){
                    dice_roll = distribution(generator);
                    str = str + table[dice_roll];
                }
                if(k == 0)      output1 << str << endl;
                else if(k == 1) output2 << str << endl;          
                else            output3 << str << endl;
                i++;
            }
        }
    }



}