#ifndef CLICK_MIDDLWBOXIDS_HH
#define CLICK_MIDDLWBOXIDS_HH
#include <click/element.hh>
#include <deque>
#include <unordered_map>
#include <fstream>
#include "veritools.hh"

CLICK_DECLS

// need server config file
class MiddleboxIDS : public Element {
public:
	MiddleboxIDS() CLICK_COLD;

	const char *class_name() const { return "MiddleboxIDS"; }
	const char *port_count() const { return PORTS_1_1; }
	const char *processing() const { return PUSH_TO_PULL; }

	int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
	bool can_live_reconfigure() const { return true; }

	int initialize(ErrorHandler *errh);

	void push(int port, Packet *p);
	Packet* pull(int port);

    std::map<int, std::set<int>> selected_nodes;
    std::map<int, std::vector<int>> selected_flows;//batchID-->flowIDs
    std::ofstream pkt_node_info_writer;

protected:
	int validTotalPkgCount;

	int readyToSendRoot;
	std::string preTime;
	std::string startTime;
	elementCounter boxCounter;
	std::ofstream boxLogger;
	std::ofstream pktLogger;

    int temp_PKTs_size;
    std::string cnt1Time;

	std::vector<std::string> eleContainer;
	std::vector<std::string> pktContainer;

	void buildTreeAndSendRootPkt(boxBatch& batch);

    void send_merkle_tree(int batchID, std::vector<int> flowIDs);

    void output_tree_node_proof(int batchID);

	std::unordered_map<uint32_t, boxBatch> batches;

	std::deque<Packet*> ready_packet;

	double boxTotalTime;

	PMAdaptor* pm_engine;
	PatternSet patterns;

	std::string activityTime;
};

CLICK_ENDDECLS
#endif
