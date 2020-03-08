require("click_verimb")


define($BATCH_SIZE 1024);
define($EXP_SIZE 102600);
define($VERIFY 0);
define($DISABLE_NETWORK 1);
define($BASELINE 0);
define($QUEYR_TABLE 0);
define($IN_CHAIN 0);

box :: MiddleboxIDS(
BATCH_SIZE $BATCH_SIZE, EXP_SIZE $EXP_SIZE,
VERIFY $VERIFY, DISABLE_NETWORK $DISABLE_NETWORK, BASELINE $BASELINE,
QUEYR_TABLE $QUEYR_TABLE, IN_CHAIN $IN_CHAIN);

FromDump(./reality01.pcap, STOP true)
	-> [0]box
	-> ToDump(./m59.pcap);



//FromDevice(eth0)
//	-> [0]box
//	-> ToDump(./m59.pcap);
