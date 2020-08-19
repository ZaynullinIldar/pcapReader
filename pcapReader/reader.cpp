#include "reader.h"

void printGlobalHeader(const pcap_file_header& ghdr)
{
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "magic: " << std::hex << ghdr.magic << std::dec << std::endl;
	std::cout << "version_major: " << ghdr.version_major << std::endl;
	std::cout << "version_minor: " << ghdr.version_minor << std::endl;
	std::cout << "this zone: " << ghdr.thiszone << std::endl;
	std::cout << "sigfigs: " << ghdr.sigfigs << std::endl;
	std::cout << "snaplen: " << ghdr.snaplen << std::endl;
	std::cout << "linktype: " << ghdr.linktype << std::endl; //1 is Ethernet
}

ether_header readEthernetHeader(const uint8_t* data)
{
	ether_header* ethHdrPtr;
	ether_header ethHdr;
	ethHdrPtr = (ether_header*)(data);
	memcpy(&ethHdr, ethHdrPtr, sizeof(ethHdr));
	ethHdr.ether_type = ntohs(ethHdr.ether_type);
	return ethHdr;
}

std::string strEthType(uint16_t ethType)
{
	switch (ethType)
	{
	case ETHERTYPE_PUP: return "PUP";
	case ETHERTYPE_SPRITE: return "SPRITE";
	case ETHERTYPE_IP: return "IP";
	case ETHERTYPE_ARP: return "ARP";
	case ETHERTYPE_REVARP: return "REVARP";
	case ETHERTYPE_AT: return "AT";
	case ETHERTYPE_AARP: return "AARP";
	case ETHERTYPE_VLAN: return "VLAN";
	case ETHERTYPE_IPX: return "IPX";
	case ETHERTYPE_IPV6: return "IPv6";
	case ETHERTYPE_LOOPBACK: return "LOOPBACK";
	}
	return "UNKNOWN";
}

void writeEthernetHeader(const ether_header& ethHdr)
{
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "dest addr: " << std::hex;
	for (int i = 0; i < ETH_ALEN; ++i)
	{
		std::cout << (int)ethHdr.ether_dhost[i] << " ";
	}
	std::cout << std::endl;
	std::cout << "src addr : ";
	for (int i = 0; i < ETH_ALEN; ++i)
	{
		std::cout << (int)ethHdr.ether_shost[i] << " ";
	}
	std::cout << std::endl;
	std::cout << "eth type : ";
	std::cout << strEthType(ethHdr.ether_type) << std::dec << std::endl;
}

arphdr readArpHeader(const uint8_t* data)
{
	arphdr* arpHdrPtr;
	arphdr aHdr;
	arpHdrPtr = (arphdr*)(data);
	memcpy(&aHdr, arpHdrPtr, sizeof(aHdr));
	aHdr.ar_hrd = ntohs(aHdr.ar_hrd);
	aHdr.ar_pro = ntohs(aHdr.ar_pro);
	aHdr.ar_op = ntohs(aHdr.ar_op);
	return aHdr;
}

std::string strHw(unsigned short int hw)
{
	switch (hw)
	{
	case ARPHRD_NETROM: return "NETROM";
	case ARPHRD_ETHER: return "ETHER";
	case ARPHRD_EETHER: return "EETHER";
	case ARPHRD_AX25: return "AX25";
	case ARPHRD_PRONET: return "PRONET";
	case ARPHRD_CHAOS: return "CHAOS";
	case ARPHRD_IEEE802: return "IEEE802";
	case ARPHRD_ARCNET: return "ARCNET";
	case ARPHRD_APPLETLK: return "APPLETLK";
	case ARPHRD_DLCI: return "DLCI";
	case ARPHRD_ATM: return "ATM";
	case ARPHRD_METRICOM: return "METRICOM";
	case ARPHRD_IEEE1394: return "IEEE1394";
	case ARPHRD_EUI64: return "EUI64";
	case ARPHRD_INFINIBAND: return "INFINIBAND";
	}
	return "UNKNOWN";
}

std::string strArpOpcode(unsigned short int op)
{
	switch (op)
	{
	case ARPOP_REQUEST: return "REQUEST";
	case ARPOP_REPLY: return "REPLY";
	case ARPOP_RREQUEST:return "RREQUEST";
	case ARPOP_RREPLY: return "RREPLY";
	case ARPOP_InREQUEST: return "InREQUEST";
	case ARPOP_InREPLY: return "InREPLY";
	case ARPOP_NAK: return "NAK";
	}
	return "UNKNOWN";
}

void writeArpHeader(const arphdr& aHdr)
{
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "format hw addr  : " << strHw(aHdr.ar_hrd) << std::endl;
	std::cout << "format prot addr: " << strEthType(aHdr.ar_pro) << std::endl;
	std::cout << "length hw addr  : " << (int)aHdr.ar_hln << " bytes" << std::endl;
	std::cout << "length prot addr: " << (int)aHdr.ar_pln << " bytes" << std::endl;
	std::cout << "ARP opcode      : " << strArpOpcode(aHdr.ar_op) << std::dec << std::endl;
}

arpdata readArpData(const uint8_t* data)
{
	arpdata aData;
	arpdata* aDataPtr;
	aDataPtr = (arpdata*)(data);
	memcpy(&aData, aDataPtr, sizeof(aData));
	return aData;
}

void writeArpData(const arpdata& aData)
{
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "sender hw addr: " << std::hex;
	for (int i = 0; i < ETH_ALEN; ++i)
	{
		std::cout << (int)aData.senderHwAddr[i] << " ";
	}
	std::cout << std::endl;
	std::cout << "sender ip addr: " << std::dec;
	for (int i = 0; i < 4; ++i)
	{
		std::cout << (int)aData.senderIpAddr[i] << ".";
	}
	std::cout << std::endl;
	std::cout << "target hw addr: " << std::hex;
	for (int i = 0; i < ETH_ALEN; ++i)
	{
		std::cout << (int)aData.targetHwAddr[i] << " ";
	}
	std::cout << std::endl;
	std::cout << "target ip addr: " << std::dec;
	for (int i = 0; i < 4; ++i)
	{
		std::cout << (int)aData.targetIpAddr[i] << ".";
	}
	std::cout << std::endl;
}

ip_t readIpHeader(const uint8_t* data)
{
	ip_t ipHdr;
	ip_t* ipHdrPtr;
	ipHdrPtr = (ip_t*)(data);
	memcpy(&ipHdr, ipHdrPtr, sizeof(ipHdr));
	ipHdr.ip_len = ntohs(ipHdr.ip_len);
	ipHdr.ip_id = ntohs(ipHdr.ip_id);
	ipHdr.ip_off = ntohs(ipHdr.ip_off);
	ipHdr.ip_sum = ntohs(ipHdr.ip_sum);
	return ipHdr;
}

std::string strProtInIp(uint8_t prot)
{
	switch (prot)
	{
	case IP_ICMP: return "ICMP";
	case IP_TCP: return "TCP";
	case IP_UDP: return "UDP";
		//add some protocols
	}
	return "UNKNOWN";
}

void writeIpHeader(const ip_t& ipHdr)
{
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "header length: " << (ipHdr.ip_hlv & 0x0F) * 4 << " bytes" << std::endl;
	std::cout << "version: " << (ipHdr.ip_hlv >> 4) << std::endl;
	std::cout << "type of service: " << std::hex << (int)ipHdr.ip_tos << std::dec << std::endl;
	std::cout << "total length: " << ipHdr.ip_len << " bytes" << std::endl;
	std::cout << "identification: " << std::hex << ipHdr.ip_id << std::dec << std::endl;
	std::cout << "fragment offset field: " << ipHdr.ip_off << std::endl;
	std::cout << "time to live: " << (int)ipHdr.ip_ttl << std::endl;
	std::cout << "protocol: " << strProtInIp(ipHdr.ip_p) << std::dec << std::endl;
	std::cout << "checksum: " << std::hex << ipHdr.ip_sum << std::dec << std::endl;
	std::cout << "source address: " << inet_ntoa(ipHdr.ip_src) << std::endl;
	std::cout << "destin address: " << inet_ntoa(ipHdr.ip_dst) << std::endl;
}

tcp_t readTcpHeader(const uint8_t* data)
{
	tcp_t tcpHdr;
	tcp_t* tcpHdrPtr;
	tcpHdrPtr = (tcp_t*)(data);
	memcpy(&tcpHdr, tcpHdrPtr, sizeof(tcpHdr));
	tcpHdr.src_port = ntohs(tcpHdr.src_port);
	tcpHdr.dst_port = ntohs(tcpHdr.dst_port);
	tcpHdr.seq = ntohl(tcpHdr.seq);
	tcpHdr.ack = ntohl(tcpHdr.ack);
	tcpHdr.window_size = ntohs(tcpHdr.window_size);
	tcpHdr.checksum = ntohs(tcpHdr.checksum);
	tcpHdr.urgent_p = ntohs(tcpHdr.urgent_p);
	return tcpHdr;
}

std::string strTcpFlags(uint8_t flags)
{
	std::string strFlags = "";
	if (flags & 0x01)
	{
		strFlags += "FIN ";
	}
	if (flags & 0x02)
	{
		strFlags += "SYN ";
	}
	if (flags & 0x04)
	{
		strFlags += "RST ";
	}
	if (flags & 0x08)
	{
		strFlags += "PSH ";
	}
	if (flags & 0x10)
	{
		strFlags += "ACK ";
	}
	if (flags & 0x20)
	{
		strFlags += "URG ";
	}
	return strFlags;
}

void writeTcpHeader(const tcp_t& tcpHdr)
{
	//std::bitset<8> flags = tcpHdr.flags;
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "src port: " << tcpHdr.src_port << std::endl;
	std::cout << "dst port: " << tcpHdr.dst_port << std::endl;
	std::cout << "seq: " << std::hex << tcpHdr.seq << std::endl;
	std::cout << "ack: " << tcpHdr.ack << std::dec << std::endl;
	std::cout << "header length: " << (tcpHdr.data_offset >> 4) * 4 << " bytes" << std::endl;
	//std::cout << "flags: " << flags << std::endl;
	std::cout << "flags: " << strTcpFlags(tcpHdr.flags) << std::endl;
	std::cout << "window size: " << tcpHdr.window_size << " bytes" << std::endl;
	std::cout << "checksum: " << std::hex << tcpHdr.checksum << std::dec << std::endl;
	std::cout << "urgent ptr: " << tcpHdr.urgent_p << std::endl;
}

udp_t readUdpHeader(const uint8_t* data)
{
	udp_t udpHdr;
	udp_t* udpHdrPtr;
	udpHdrPtr = (udp_t*)(data);
	memcpy(&udpHdr, udpHdrPtr, sizeof(udpHdr));
	udpHdr.source = ntohs(udpHdr.source);
	udpHdr.dest = ntohs(udpHdr.dest);
	udpHdr.len = ntohs(udpHdr.len);
	udpHdr.check = ntohs(udpHdr.check);
	return udpHdr;
}

void writeUdpHeader(const udp_t& udpHdr)
{
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "source port: " << udpHdr.source << std::endl;
	std::cout << "destination port: " << udpHdr.dest << std::endl;
	std::cout << "datagram length: " << udpHdr.len << " bytes" << std::endl;
	std::cout << "checksum: " << udpHdr.check << std::endl;
}

icmphdr readIcmpHeader(const uint8_t* data) //FIXME!
{
	icmphdr icmpHdr;
	icmphdr* icmpHdrPtr;
	icmpHdrPtr = (icmphdr*)(data);
	memcpy(&icmpHdr, icmpHdrPtr, sizeof(icmpHdr));
	icmpHdr.checksum = ntohs(icmpHdr.checksum);
	icmpHdr.un.echo.id = ntohs(icmpHdr.un.echo.id);
	icmpHdr.un.echo.sequence = ntohs(icmpHdr.un.echo.sequence);
	icmpHdr.un.gateway = ntohl(icmpHdr.un.gateway);
	//icmpHdr.un.frag.__glibc_reserved = ntohs(icmpHdr.un.frag.__glibc_reserved);
	icmpHdr.un.frag.mtu = ntohs(icmpHdr.un.frag.mtu);
	return icmpHdr;
}

void writeIcmpHeader(const icmphdr& icmpHdr)
{
	std::cout << "-----------------------------------" << std::endl;
	std::cout << "type:     " << icmpHdr.type << std::endl;
	std::cout << "code:     " << icmpHdr.code << std::endl;
	std::cout << "checksum: " << icmpHdr.checksum << std::endl;
	//
}


	LengthCollector::LengthCollector()
	{

	}
	LengthCollector::~LengthCollector()
	{

	}
	void LengthCollector::collectLength(int length)
	{
		if (length <= 64) ++m_distrib[0];
		else
			if (length >= 65 && length <= 255) ++m_distrib[1];
			else
				if (length >= 256 && length <= 511) ++m_distrib[2];
				else
					if (length >= 512 && length <= 1023) ++m_distrib[3];
					else
						if (length >= 1024 && length <= 1518) ++m_distrib[4];
						else
							if (length >= 1519) ++m_distrib[5];
	}

	void LengthCollector::printDistribution()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "length distribution of packets" << std::endl;
		std::cout << "<= 64      : " << m_distrib[0] << " packets" << std::endl;
		std::cout << "[64,255]   : " << m_distrib[1] << " packets" << std::endl;
		std::cout << "[256,511]  : " << m_distrib[2] << " packets" << std::endl;
		std::cout << "[512,1023] : " << m_distrib[3] << " packets" << std::endl;
		std::cout << "[1024,1518]: " << m_distrib[4] << " packets" << std::endl;
		std::cout << ">= 1519    : " << m_distrib[5] << " packets" << std::endl;
	}

	

	ProtocolCollector::ProtocolCollector()
	{

	}

	ProtocolCollector::~ProtocolCollector()
	{

	}

	void ProtocolCollector::collectProtocol(const uint8_t* mem)
	{
		m_ethHdrPtr = (ether_header*)(mem);
		if (ntohs(m_ethHdrPtr->ether_type) != ethernetType::ETHTYPE_IP) //non IPv4
		{
			++m_protDistribution[0];
		}
		else
			if (ntohs(m_ethHdrPtr->ether_type) == ethernetType::ETHTYPE_IP) //IPv4
			{
				++m_protDistribution[1];
				m_ipHdrPtr = (ip_t*)(mem + sizeof(ether_header));
				if ((m_ipHdrPtr->ip_p) == ipType::IP_ICMP) // ICMP/IP
				{
					++m_protDistribution[2];
				}
				else
					if ((m_ipHdrPtr->ip_p) == ipType::IP_TCP) // TCP/IP
					{
						++m_protDistribution[3];
					}
					else
						if ((m_ipHdrPtr->ip_p) == ipType::IP_UDP) // UDP/IP
						{
							++m_protDistribution[4];
						}
			}
	}


	void ProtocolCollector::printDistribution()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "protocol distribution of packets" << std::endl;
		std::cout << "non IPv4: " << m_protDistribution[0] << " packets" << std::endl;
		std::cout << "IPv4    : " << m_protDistribution[1] << " packets" << std::endl;;
		std::cout << "ICMP    : " << m_protDistribution[2] << " packets" << std::endl;;
		std::cout << "TCP     : " << m_protDistribution[3] << " packets" << std::endl;;
		std::cout << "UDP     : " << m_protDistribution[4] << " packets" << std::endl;;
	}

	TcpFlagsCollector::TcpFlagsCollector()
	{

	}

	TcpFlagsCollector::~TcpFlagsCollector()
	{

	}

	void TcpFlagsCollector::collectTcpFlags(const uint8_t* mem)
	{
		m_ethHdrPtr = (ether_header*)(mem);
		if (ntohs(m_ethHdrPtr->ether_type) == ethernetType::ETHTYPE_IP)
		{
			m_ipHdrPtr = (ip_t*)(mem + sizeof(ether_header));
			if (m_ipHdrPtr->ip_p == ipType::IP_TCP)
			{
				m_tcpHdrPtr = (tcp_t*)(mem + sizeof(ether_header) + ((m_ipHdrPtr->ip_hlv) & 0x0F) * 4);

				doDistribution(m_tcpHdrPtr->flags);
			}
		}
	}

	void TcpFlagsCollector::printDistribution()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "TCP flags distribution" << std::endl;
		std::cout << "SYN    : " << m_flagDistribution[0] << std::endl;
		std::cout << "SYN+ACK: " << m_flagDistribution[1] << std::endl;
		std::cout << "ACK    : " << m_flagDistribution[2] << std::endl;
		std::cout << "FIN+ACK: " << m_flagDistribution[3] << std::endl;
		std::cout << "RST    : " << m_flagDistribution[4] << std::endl;
		std::cout << "RST+ACK: " << m_flagDistribution[5] << std::endl;
	}
	
	UniqueValueCollector::UniqueValueCollector()
	{

	}

	UniqueValueCollector::~UniqueValueCollector()
	{

	}

	void UniqueValueCollector::collectInfo(const uint8_t* mem)
	{
		m_ethHdrPtr = (ether_header*)(mem);

		m_src_mac.clear();
		for (int i = 0; i < 6; ++i)
		{
			m_src_mac.push_back(m_ethHdrPtr->ether_shost[i]);
		}
		m_array_src_mac.push_back(m_src_mac);

		m_dst_mac.clear();
		for (int i = 0; i < 6; ++i)
		{
			m_dst_mac.push_back(m_ethHdrPtr->ether_dhost[i]);
		}
		m_array_dst_mac.push_back(m_dst_mac);


		if (ntohs(m_ethHdrPtr->ether_type) == ethernetType::ETHTYPE_IP)
		{
			m_ipHdrPtr = (ip_t*)(mem + sizeof(ether_header));
			m_array_src_ip.push_back(m_ipHdrPtr->ip_src);
			m_array_dst_ip.push_back(m_ipHdrPtr->ip_dst);

			if (m_ipHdrPtr->ip_p == ipType::IP_TCP)
			{
				m_tcpHdrPtr = (tcp_t*)(mem + sizeof(ether_header) + ((m_ipHdrPtr->ip_hlv) & 0x0F) * 4);
				m_array_src_port.push_back(ntohs(m_tcpHdrPtr->src_port));
				m_array_dst_port.push_back(ntohs(m_tcpHdrPtr->dst_port));
			}
			else
				if (m_ipHdrPtr->ip_p == ipType::IP_UDP)
				{
					m_udpHdrPtr = (udp_t*)(mem + sizeof(ether_header) + ((m_ipHdrPtr->ip_hlv) & 0x0F) * 4);
					m_array_src_port.push_back(ntohs(m_udpHdrPtr->source));
					m_array_dst_port.push_back(ntohs(m_udpHdrPtr->dest));
				}
		}


	}

	void UniqueValueCollector::printSrcMacs()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "src macs: " << std::endl;
		for (auto const& elem : m_array_src_mac)
		{
			for (int i = 0; i < 6; ++i)
			{
				std::cout << std::hex << (int)elem[i] << " ";
			}
			std::cout << std::endl;
		}
		std::cout << std::dec;
	}

	void UniqueValueCollector::printDstMacs()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "dst macs: " << std::endl;
		for (auto const& elem : m_array_dst_mac)
		{
			for (int i = 0; i < 6; ++i)
			{
				std::cout << std::hex << (int)elem[i] << " ";
			}
			std::cout << std::endl;
		}
		std::cout << std::dec;
	}

	void UniqueValueCollector::printSrcCollectionMac()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "src collection of  macs: " << std::endl;
		m_collection_src_mac.clear();
		m_collection_src_mac = formCollection(m_array_src_mac);
		for (auto const& elem : m_collection_src_mac)
		{
			for (int i = 0; i < 6; ++i)
			{
				std::cout << std::hex << (int)elem[i] << " ";
			}
			std::cout << std::endl;
		}
		std::cout << std::dec;
	}

	void UniqueValueCollector::printDstCollectionMac()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "dst collection of  macs: " << std::endl;
		m_collection_dst_mac.clear();
		m_collection_dst_mac = formCollection(m_array_dst_mac);
		for (auto const& elem : m_collection_dst_mac)
		{
			for (int i = 0; i < 6; ++i)
			{
				std::cout << std::hex << (int)elem[i] << " ";
			}
			std::cout << std::endl;
		}
		std::cout << std::dec;
	}

	void UniqueValueCollector::printSrcIps()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "src ips: " << std::endl;
		for (const auto& elem : m_array_src_ip)
		{
			std::cout << inet_ntoa(elem) << std::endl;
		}
	}

	void UniqueValueCollector::printDstIps()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "dst ips: " << std::endl;
		for (const auto& elem : m_array_dst_ip)
		{
			std::cout << inet_ntoa(elem) << std::endl;
		}
	}

	void UniqueValueCollector::printSrcCollectionIps()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "src collection of  IPs: " << std::endl;
		m_collection_src_ip.clear();
		m_collection_src_ip = formCollection(m_array_src_ip);
		for (auto const& elem : m_collection_src_ip)
		{
			std::cout << inet_ntoa(elem) << std::endl;
		}
	}

	void UniqueValueCollector::printDstCollectionIps()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "dst collection of  IPs: " << std::endl;
		m_collection_dst_ip.clear();
		m_collection_dst_ip = formCollection(m_array_dst_ip);
		for (auto const& elem : m_collection_dst_ip)
		{
			std::cout << inet_ntoa(elem) << std::endl;
		}
	}

	void UniqueValueCollector::printSrcPorts()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "src ports: " << std::endl;
		for (const auto& elem : m_array_src_port)
		{
			std::cout << elem << std::endl;
		}
	}

	void UniqueValueCollector::printDstPorts()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "dst ports: " << std::endl;
		for (const auto& elem : m_array_dst_port)
		{
			std::cout << elem << std::endl;
		}
	}

	void UniqueValueCollector::printSrcCollectionPorts()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "src collection of  ports: " << std::endl;
		m_collection_src_port.clear();
		m_collection_src_port = formCollection(m_array_src_port);
		for (auto const& elem : m_collection_src_port)
		{
			std::cout << elem << std::endl;
		}
	}

	void UniqueValueCollector::printDstCollectionPorts()
	{
		std::cout << "-----------------------------------" << std::endl;
		std::cout << "dst collection of  ports: " << std::endl;
		m_collection_dst_port.clear();
		m_collection_dst_port = formCollection(m_array_dst_port);
		for (auto const& elem : m_collection_dst_port)
		{
			std::cout << elem << std::endl;
		}
	}

	void UniqueValueCollector::printNumberOfUniqueValues()
	{
		std::cout << "-----------------------------------" << std::endl;

		m_collection_src_mac.clear();
		m_collection_src_mac = formCollection(m_array_src_mac);
		std::cout << "number of unique src macs: " << m_collection_src_mac.size() << std::endl;
		m_collection_dst_mac.clear();
		m_collection_dst_mac = formCollection(m_array_dst_mac);
		std::cout << "number of unique dst macs: " << m_collection_dst_mac.size() << std::endl;

		m_collection_src_ip.clear();
		m_collection_src_ip = formCollection(m_array_src_ip);
		std::cout << "number of unique src IPs: " << m_collection_src_ip.size() << std::endl;
		m_collection_dst_ip.clear();
		m_collection_dst_ip = formCollection(m_array_dst_ip);
		std::cout << "number of unique dst IPs: " << m_collection_dst_ip.size() << std::endl;

		m_collection_src_port.clear();
		m_collection_src_port = formCollection(m_array_src_port);
		std::cout << "number of unique src ports: " << m_collection_src_port.size() << std::endl;
		m_collection_dst_port.clear();
		m_collection_dst_port = formCollection(m_array_dst_port);
		std::cout << "number of unique dst ports: " << m_collection_dst_port.size() << std::endl;
	}