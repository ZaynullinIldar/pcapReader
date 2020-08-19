#include "reader.h"


int main(int argc , char* argv[])
{
	std::string filename;
	if (argc == 2) 
	{
		filename = argv[1];
		
	}
	else
	{
		std::cout << "Usage: ./reader [filename]" << std::endl;
		return -1;
	}
	
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(filename.c_str(),errbuf);
	if (handle == nullptr)
	{
		std::cout << "pcap_open_offline() failed: " << errbuf << std::endl;
		return -1;
	}
	pcap_pkthdr pcaphdr;
	const uint8_t* packet;

	int frameCounter = 0;
	int lengthOfFrames = 0;
	LengthCollector    lenColl;
	ProtocolCollector  protColl;
	TcpFlagsCollector tcpFlagsColl;
	UniqueValueCollector uniqValColl;

	while (packet = pcap_next(handle, &pcaphdr))
	{
		++frameCounter;
		lengthOfFrames  += pcaphdr.len;
		lenColl.collectLength(pcaphdr.len);
		protColl.collectProtocol(packet);
		tcpFlagsColl.collectTcpFlags(packet);
		uniqValColl.collectInfo(packet);
	}
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "file: "  << filename << std::endl;
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "total frames: " << frameCounter << std::endl;
	std::cout << "total length of frames: " << lengthOfFrames << " bytes" << std::endl;
	lenColl.printDistribution();
	protColl.printDistribution();
	tcpFlagsColl.printDistribution();
	uniqValColl.printNumberOfUniqueValues();
	pcap_close(handle);
	return 0;
}