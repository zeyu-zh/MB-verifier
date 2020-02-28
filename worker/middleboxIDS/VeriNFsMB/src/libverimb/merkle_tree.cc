#include "merkle_tree.h"
#include "veri_header.h"
#include "./base64/base64.h"
#include <string>
using namespace std;



MerkleTree::MerkleTree()
{
	root = 0;
}

MerkleTree::~MerkleTree()
{
	if (root)
	{
		delete[] root;
	}
}

MerkleTree::MerkleTree(const uint32_t height_input, const std::vector<std::string>& data)
	:height(height_input)
{
	buildtree(height, data);
}

void MerkleTree::buildtree(const uint32_t height, const std::vector<std::string>& data)
{
	int hashCount = 0;

	//malloc tree space
	const int treeNodeCount = (1 << height) - 1;
	root = new TreeNode[treeNodeCount];
	for (int i = 1; i < treeNodeCount; i++)
	{
		root[i].parent = root + (i - 1) / 2;
	}

	// copy leavesLayer value
	const int leafLayerNodeCount = 1 << (height - 1);
	TreeNode* leavesLayer = root + leafLayerNodeCount - 1;
	auto iter = data.begin();
	for (int i = 0; i < leafLayerNodeCount; i++)
	{
		leavesLayer++->hashValue.assign(*iter++);
	}

	int currentLayer = height - 1;
	while (currentLayer != 0)
	{
		int baseIndex = (1 << (currentLayer - 1)) - 1;
		leavesLayer = root + baseIndex;
		for (int i = 0; i < (1 << (currentLayer - 1)); i++)
		{
			string value(root[(baseIndex + i) * 2 + 1].hashValue);
			value.append(root[(baseIndex + i) * 2 + 2].hashValue);
			(leavesLayer+i)->hashValue.assign(encTools::SHA256(value));
            
			hashCount += 1;
		}
		currentLayer -= 1;
	}
	//click_chatter("tree height is %d, tree node is %d", height, hashCount);
	
}

string MerkleTree::getRoot()
{
	return root->hashValue;
}

string MerkleTree::query(string leafHash)
{
	string res;
	//TreeNode* leavesLayer = root + (1 << (height - 1)) - 1;
	
	int loc;
	for (loc = (1 << (height - 1)) - 1; loc < (1 << height) - 1; loc++)
	{
		if (root[loc].hashValue == leafHash)
		{
			while (loc != 0)
			{
				if (loc % 2 == 0)
				{
					loc += 1;
				}
				else
				{
					loc -= 1;
				}

				res.append(root[loc].hashValue);
				loc = (loc - 1) / 2;
			}
			break;
		}
	}
	return res;
}

std::string MerkleTree::query(int node_num) {
    
     
	//click_chatter("%d length is:%d",node_num,root[node_num].hashValue.length());         
	//click_chatter("%d:%s",node_num,root[node_num].hashValue.c_str());
     
    //click_chatter("%d:%s",node_num,root[node_num].hashValue.c_str());
    char temp[1024];
    
    int len = base64_encode((const unsigned char *)(root[node_num].hashValue.c_str()), root[node_num].hashValue.length(), temp);
    
    char temp1[len];
    strncpy(temp1, temp, len);

    string str(temp1);

    //click_chatter("%d:%s",node_num,str.c_str());



    return str;
}
