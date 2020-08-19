#include "reader.h"
#include <filesystem>

int main(int argc , char* argv[])
{
	std::string dir;
	if (argc == 2) 
	{
		dir = argv[1];
		if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir))
		{
			std::cerr << "item " << dir << " does not exist or not dir" << std::endl;
			return -1;
		}
			
	}
	else
	{
		std::cerr << "Usage: ./reader [dir]" << std::endl;
		return -1;
	}  
	
	std::vector<std::string> filelist;

	for (const auto& item : std::filesystem::directory_iterator(dir))
	{
		filelist.push_back(item.path());
	}

	for (const auto& file : filelist)
	{
		pcap_t* handle;
		char errbuf[PCAP_ERRBUF_SIZE];
		handle = pcap_open_offline(file.c_str(), errbuf);
		if (handle == nullptr)
		{
			std::cerr << "pcap_open_offline() failed: " << errbuf << std::endl;
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
			lengthOfFrames += pcaphdr.len;
			lenColl.collectLength(pcaphdr.len);
			protColl.collectProtocol(packet);
			tcpFlagsColl.collectTcpFlags(packet);
			uniqValColl.collectInfo(packet);
		}
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "file: " << file << std::endl;
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "total frames: " << frameCounter << std::endl;
		std::cout << "total length of frames: " << lengthOfFrames << " bytes" << std::endl;
		lenColl.printDistribution();
		protColl.printDistribution();
		tcpFlagsColl.printDistribution();
		uniqValColl.printNumberOfUniqueValues();
		pcap_close(handle);
	}
	return 0;
}