#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/integers.hh>
#include <fstream>
#include <iostream>
#include <cmath>
#include <sys/socket.h>
#include "middleboxIDS.hh"
#include "veritools.hh"
#include "../libverimb/ac/aho_corasick.h"
#include "../libverimb/ac/ac_adaptor.h"

CLICK_DECLS

using namespace std;

MiddleboxIDS::MiddleboxIDS()
{
}


static bool veriSwitch = true;////从文件读入时为false，从网卡读入为true
static bool justSend = false;
static bool localMode = false;
static bool bothway = false;
static int  batch_element_size = 1024;
static int  maxPktUsed = 1024 * 10 * 10 + 200;
static bool lbInTheChain = false;
static bool fwInTheChain = false;
static bool idsInTheChain = false;//从文件读入时为false，从网卡读入为true

int
MiddleboxIDS::configure(Vector<String> &conf, ErrorHandler* errh)
{

    //if (Args(conf, errh)
	//	.complete() < 0)
	//{
	//	return -1;
	//}
	// Parsing
	int inChain;
	if (Args(conf, errh)
		//.read_m("PATTERN_FILE", m_config.pattern_file)
		.read_m("BATCH_SIZE", batch_element_size)
		.read_m("EXP_SIZE", maxPktUsed)
		.read_m("VERIFY", veriSwitch)
		.read_m("DISABLE_NETWORK", localMode)
		.read_m("BASELINE", justSend)
		.read_m("QUEYR_TABLE", bothway)
		.read_m("IN_CHAIN", inChain)
		.complete() < 0)
	{
		return -1;
	}

	if (inChain)
	{
		lbInTheChain = true;
		fwInTheChain = true;
		idsInTheChain = true;
	}
	else
	{
		lbInTheChain = false;
		fwInTheChain = false;
		idsInTheChain = false;
	}

	return 0;
}

int MiddleboxIDS::initialize(ErrorHandler *errh)
{
	//char strBuffer[2000];
	//// test sha256
	//const int num[] = {6, 200, 400, 600, 800, 1000, 1200};

	//for (int k = 0; k < sizeof(num) / sizeof(int); k++)
	//{
	//	std::string start = encTools::timeNow();
	//	for (int i = 0; i < 10000; i++)
	//	{
	//		string str;
	//		str.assign(strBuffer, num[k]);
	//		std::string res = encTools::SHA256(str);
	//	}
	//	std::string end = encTools::timeNow();
	//	double t = encTools::differTimeInNsec(start.data(), end.data());

	//	click_chatter("SHA %d  B data need %lf ns.\n", num[k], t);
	//}
	//click_chatter("\n\n\n\n");

	click_chatter("===============================================\n");
	click_chatter("Batch size\t:\t%d\n", batch_element_size);
	click_chatter("Packets count\t:\t%d\n", maxPktUsed);

	click_chatter("Baseline test is %s\n", justSend ? "enable" : "disable");
	click_chatter("Veri function is %s\n", veriSwitch ? "enable" : "disable");
	click_chatter("Local test is %s\n", localMode ? "enable" : "disable");
	click_chatter("Query Table is %s\n", bothway ? "enable" : "disable");
	click_chatter("Box in chain is %s\n", lbInTheChain ? "yes" : "no");

	//click_chatter("flowBased LB  is %s\n", sampleLB ? "enable" : "disable");
	//click_chatter("flowBased FW  is %s\n", sampleFW ? "enable" : "disable");
	//click_chatter("flowBased IDS is %s\n", sampleIDS ? "enable" : "disable");
	click_chatter("===============================================\n");
	std::string start = encTools::timeNow();
	click_chatter("===============================================\n");
	std::string end = encTools::timeNow();
	click_chatter("output one line use %lf ns.\n", encTools::differTimeInNsec(start.data(), end.data()));

	boxLogger.open(string(eleOutputPath).append(outputExtension));
	pktLogger.open(string(pktOutputPath).append(outputExtension));
	pktContainer.reserve(maxPktUsed);

    pktLogger<<"pkt大小(Byte),用时(ns)"<<endl;

	validTotalPkgCount = 0;
	boxCounter.no = 1;

	VeriTools::initIDS(&pm_engine, patterns);
	click_chatter("Load %d patterns.\n", patterns.size());
    
    pkt_node_info_writer.open("pkt_node_info.txt");
	
    boxTotalTime = 0;

	preTime = encTools::timeNow();
	activityTime = encTools::timeNow();

	return 0;
}

void MiddleboxIDS::push(int port, Packet * p_in)
{
	//click_chatter("push()\n");
    if (localMode&& validTotalPkgCount >= maxPktUsed - 10)
	{
		for (auto it = pktContainer.begin(); it != pktContainer.end(); ++it)
		{
			pktLogger << *it;
		}
		click_chatter("===============================================\n");
		click_chatter("Write file end.\n");
		click_chatter("===============================================\n");
		validTotalPkgCount = 0;
	}

	std::string beginTime = encTools::timeNow();






    if (!VeriTools::isTestPacket(p_in))
	{
		click_chatter("is not test_packer\n");
        if (justSend)
		{
			click_chatter("is justSend\n");
            WritablePacket *p = p_in->uniqueify();
			//########################  different in each box
			VeriTools::reDirectionPacket(p, boxIDS_src_ip, boxIDS_src_mac, boxIDS_dst_ip, boxIDS_dst_mac);
			ready_packet.push_back(p);
			boxCounter.pktCount += 1;
			boxCounter.pktSize += p_in->length();
			boxCounter.pktPageloadSize += PktReader(p_in).getDataLength();
			VeriTools::checkElementCounter(boxCounter, preTime, eleContainer);
			++validTotalPkgCount;
			if (validTotalPkgCount == maxPktUsed)
			{
				for (auto it = eleContainer.begin(); it != eleContainer.end(); ++it)
				{
					boxLogger << *it;
				}
				click_chatter("wait to write :%d\n", validTotalPkgCount);
			}
		}
		else
		{
			   //FromDevice所有包都会到这里
            //click_chatter("isn't justSend\n");
            static bool wroteFile = false;
			static string waitTime = "";
			if (!wroteFile && (validTotalPkgCount == maxPktUsed || encTools::differTimeInNsec(activityTime.data(), encTools::timeNow().data()) > elementCounterBaseGap * 10.0))
			{
				if (waitTime.size() > 0)
				{
					if (encTools::differTimeInNsec(waitTime.data(), encTools::timeNow().data()) > elementCounterBaseGap*2)
					{
						for (auto it = eleContainer.begin(); it != eleContainer.end(); ++it)
						{
							boxLogger << *it;
						}
						for (auto it = pktContainer.begin(); it != pktContainer.end(); ++it)
						{
							pktLogger << *it;
						}
						wroteFile = true;
						click_chatter("===============================================\n");
						click_chatter("Write file end.\n");
						click_chatter("===============================================\n");
					}
				}
				else
				{
					click_chatter("===============================================\n");
					click_chatter("wait to write :%d\n", validTotalPkgCount);
					click_chatter("box avg use %lf ns.\n", boxTotalTime / maxPktUsed);
					click_chatter("===============================================\n");
					waitTime = encTools::timeNow();
				}
			}
			p_in->kill();
		}
		return;
	}
    //click_chatter("I'm at point 1.\n");
	// 1. get pkt batch
	PktReader reader(p_in);
	VeriHeader * pveri = (VeriHeader *)reader.getIpOption();
	

    	//抽样验证的包进if
    if(pveri->flowID >= 32768)
    {
        pveri->flowID = pveri->flowID - 32768;
        if (pveri->flowID == trickFlowID){
            //当前的包是最后一个用来检验的包
            //输出selected_nodes中所有节点的有效信息
            click_chatter("In the end.");
            ((ACAdaptor*)pm_engine)->ac.d_root->output_node_info(pveri->batchID, selected_nodes[pveri->batchID], ((ACAdaptor*)pm_engine)->ac.nodeHMAC);
        }
        else{
            WritablePacket *p = p_in->uniqueify();
            std::vector<int> node;
            VeriTools::patternMatching(pm_engine, p->data(), p->length(), node);
            //下面需要将pktID和node下标写入文件的一行中，空格隔开
            for(int i : node)
                selected_nodes[pveri->batchID].insert(i);
            
            pkt_node_info_writer<<pveri->batchID<<" "<<pveri->flowID<<" "<<pveri->cNum<<" "<<node.size()<<" ";
            for(int i : node)
                pkt_node_info_writer<<i<<" ";
            pkt_node_info_writer<<endl;
        }
        return;
    }
    boxBatch& batch = batches[pveri->batchID];
    //click_chatter("batchID : %d\n", pveri->batchID);
	//click_chatter("flowID : %d\n", pveri->flowID);
    if (batch.packetCount == 0)
	{
		//########################  different in each box
		VeriTools::initBoxBatch(batch, pveri->batchID, flowBasedVerify, IDS);
		batch.readyToSendRoot = false;
	}

	WritablePacket *p = 0;

	// 2. check if special pkt
    //const unsigned int trickFlowID = 0x2333;
    //传递batch中实际的包的总数目
	if (pveri->flowID == trickFlowID)
	{
		batch.batchPktSize = pveri->cNum;
		//从文件读入时，收到batch中的最后一个包
        if (!idsInTheChain)
		    batch.readyToSendRoot = true;
		if (verbose)
		    click_chatter("Recv batch size pkt, batchID:%d, size:%d\n", pveri->batchID, pveri->cNum);

		WritablePacket *p = p_in->uniqueify();
		VeriTools::reDirectionPacket(p, boxIDS_src_ip, boxIDS_src_mac, boxIDS_dst_ip, boxIDS_dst_mac);
		ready_packet.push_back(p);
	}
	else if (pveri->flowID == merkletreeRootFlowID)
	{
		//从网卡读入时，收到batch中的最后一个包
        if (idsInTheChain)
		    batch.readyToSendRoot = true;
		memcpy(batch.rootPacket, p_in->data(), p_in->length());
		if(verbose)
		    click_chatter("Recv merkle_tree root pkt, tree root count is %d.\n", ((VeriHeader*)(reader.getIpOption()))->cNum);
		p_in->kill();
	}
	else
	{
		pktCounter boxPktCounter;
		VeriTools::setPktCounter(boxPktCounter, p_in);

		// 3. add pkt to batch
		batch.packetCount++;
		pktFlow& flow = batch.flows[pveri->flowID];
		if (flow.packetCount == 0)
		{
			VeriTools::initFlow(flow, batch.batchID, pveri->flowID);
		}
		flow.packetCount++;


		// 4. do box function
		//########################  different in each 
		p = p_in->uniqueify();
		if (!p)
		{
			click_chatter("uniqueify error\n");
			return;
		}
		
        //click_chatter("get 1");

        std::vector<int> node;
        node.reserve(1);
        VeriTools::patternMatching(pm_engine, p->data(), p->length(), node);
        //click_chatter("get 2");
        
        std::string HMAC_str = "";
        for(int i = 0; i < node.size();i++)
        {
            for(int j = 0; j < 16 ; j++)
                HMAC_str+=(char)(((ACAdaptor*)pm_engine)->ac.nodeHMAC[node[i]][j]);
        }

        //click_chatter("get 2");

		VeriTools::reDirectionPacket(p, boxIDS_src_ip, boxIDS_src_mac, boxIDS_dst_ip, boxIDS_dst_mac);
		ready_packet.push_back(p);
		reader.attach(p);
		//VeriTools::showPacket(p);

		// 5. update veriInfo
		if (veriSwitch)
		{
            veriInfo& veri = batch.veriRes[flow.flowID];
			//click_chatter("%d\n", (int)VeriTools::fflowIDS(p));
            VeriTools::updateFlowVeri(veri, HMAC_str, p);//修改了内部功能实现
		}

		activityTime = encTools::timeNow();

        pktLogger<< p->length() <<","<<encTools::differTimeInNsec(beginTime.data(), activityTime.data())<<endl;

		if (!startTime.size())
		{
			startTime = activityTime;
		}
		boxPktCounter.timestamp = encTools::differTimeInNsec(startTime.data(), activityTime.data());
		startTime = activityTime;
		boxPktCounter.processTime = encTools::differTimeInNsec(beginTime.data(), activityTime.data());
		pktContainer.push_back(VeriTools::formatPktCounter(boxPktCounter));

		boxCounter.pktCount += 1;
		boxCounter.pktSize += p->length();
		boxCounter.pktPageloadSize += reader.getDataLength();
		VeriTools::checkElementCounter(boxCounter, preTime, eleContainer);//one line output
		validTotalPkgCount++;

		if (verbose)
		{
			click_chatter("process batch:%d flow:%d cum:%d pkt use time :%lf ns .\n", pveri->batchID, pveri->flowID, pveri->cNum, boxPktCounter.processTime);
		}
	}


	// 6.handle full batch
	if (veriSwitch)
		if (batch.readyToSendRoot)
			if (batch.batchPktSize == batch.packetCount)
			{
				if (batch.typeV == pktBasedVerify)
				{
					if ((batch.packetCount & batch.packetCount - 1) != 0)
					{
						click_chatter("batch packetCount error %d\n", batch.packetCount);
						return;
					}
					click_chatter("pkt based tree\n");
                    
					buildTreeAndSendRootPkt(batch);
                    output_tree_node_proof(pveri->batchID);
				}
				else
				{
					if ((batch.veriRes.size() & batch.veriRes.size() - 1) != 0)
					{
						click_chatter("batch flowCount error %d\n", batch.flows.size());
						return;
					}
					click_chatter("flow based tree\n");
                    buildTreeAndSendRootPkt(batch);
                    output_tree_node_proof(pveri->batchID);
				}
			}
			else
			{
				if (verbose)
				{
					click_chatter("batch need size %d, batch real size %d \n", batch.batchPktSize, batch.packetCount);
				}
			}
	boxTotalTime += encTools::differTimeInNsec(beginTime.data(), encTools::timeNow().data());
}

Packet* MiddleboxIDS::pull(int port) {
	Packet* p = 0;
	if (!ready_packet.empty())
	{
		p = ready_packet.front();
		ready_packet.pop_front();
	}

	return p;
}

void MiddleboxIDS::buildTreeAndSendRootPkt(boxBatch & batch)
{
	VeriTools::buildVeriTree(batch);

	WritablePacket* pktRoot = VeriTools::makeUDPPacket();
	PktReader reader(pktRoot);
	VeriHeader * pveri = (VeriHeader *)reader.getIpOption();

	VeriHeader* oldVeriHeader = (VeriHeader*)(batch.rootPacket + ether_len + ip_default_len);

	pveri->flowID = merkletreeRootFlowID;
	pveri->batchID = batch.batchID;
	pveri->cNum += oldVeriHeader->cNum + 1;

	if (pveri->cNum != 1)
	{
		if(verbose)
		click_chatter("find box chain, this box is No.%d box.\n", pveri->cNum);
		memcpy((uint8_t*)(pveri + 1) + udp_default_len, (uint8_t*)(oldVeriHeader + 1) + udp_default_len,
			encTools::SHA256_len*(pveri->cNum - 1));
	}
	memcpy((char*)(pveri + 1) + encTools::SHA256_len*(pveri->cNum - 1) + udp_default_len,
		batch.tree.getRoot().c_str(), encTools::SHA256_len);

	//########################  different in each box
	VeriTools::reDirectionPacket(pktRoot, boxIDS_src_ip, boxIDS_src_mac, boxIDS_dst_ip, boxIDS_dst_mac);
	if (verbose)
	click_chatter("batch %d root packet generated and flow count is %d, veri count is %d \n", batch.batchID, batch.flows.size(), batch.veriRes.size());

	//VeriTools::showPacket(pktRoot);
	ready_packet.push_back(pktRoot);
}

void MiddleboxIDS::output_tree_node_proof(int batchID)
{
    std::ofstream outputfile;
    std::string filename = "tree_node_of_batch_"+to_string(batchID)+".txt";
    outputfile.open (filename);

    boxBatch& batch = batches[batchID];
    for(int i = 0; i <= 2046; i++)
    {
        outputfile<<batch.tree.query(i)<<endl;
        // if(batch.tree.query(i) == "")
        //     click_chatter("batch %d node %d is 0", batchID, i);
    }
    //click_chatter(batch.tree.query(1023).c_str());
    //click_chatter(batch.tree.query(1024).c_str());
    //click_chatter(batch.tree.query(511).c_str());
    outputfile.close();
}

void MiddleboxIDS::send_merkle_tree(int batchID, vector<int> flowIDs) {
    boxBatch& batch = batches[batchID];
    //根结点commitment：batch.tree.getRoot();
    set<int> selected_leaves;
    for(int i : flowIDs)
        selected_leaves.insert(batch.flow_in_tree[i]);
    int temp_map[2048];
    for(int i = 0; i <= 2046; i++)
        temp_map[i] = 0;
    for(int i : selected_leaves)
    {
        temp_map[i] = 1;
        if(i%2==1)
            temp_map[i+1] = 1;
        else
            temp_map[i-1] = 1;
        
        
        int temp_i = (i-1)/2;
        while(temp_i != 0)
        {
            temp_map[temp_i] = -1;
            if(temp_i%2==1 && temp_map[temp_i+1] == 0)
                temp_map[temp_i+1] = 1;
            else if(temp_i%2==0 && temp_map[temp_i-1] == 0)
                temp_map[temp_i-1] = 1;
            temp_i = (temp_i - 1)/2;
        }
    }

    for(int i = 0; i <= 2046; i++) {
        if(temp_map[i] == 1)
        {
            //本行写入batch.tree.query(i);
        }
        else
        {
            //本行写入空字符串
        }
    }//文件共2047行

        
}


CLICK_ENDDECLS
EXPORT_ELEMENT(MiddleboxIDS)
ELEMENT_MT_SAFE(MiddleboxIDS)
ELEMENT_LIBS(-lverimb -lcryptopp)
