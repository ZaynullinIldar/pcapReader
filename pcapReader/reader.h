#ifndef READER_H
#define READER_H

#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <cstring>
#include <vector>
#include <array>
#include <bitset>

void printGlobalHeader(const pcap_file_header& ghdr);

ether_header readEthernetHeader(const uint8_t* data);

std::string strEthType(uint16_t ethType);

void writeEthernetHeader(const ether_header& ethHdr);

arphdr readArpHeader(const uint8_t* data);

std::string strHw(unsigned short int hw);

std::string strArpOpcode(unsigned short int op);

void writeArpHeader(const arphdr& aHdr);

struct arpdata
{
	unsigned char senderHwAddr[ETH_ALEN];
	unsigned char senderIpAddr[4];
	unsigned char targetHwAddr[ETH_ALEN];
	unsigned char targetIpAddr[4];
};

arpdata readArpData(const uint8_t* data);

void writeArpData(const arpdata& aData);

struct ip_t
{
	uint8_t ip_hlv;
	uint8_t ip_tos;
	unsigned short ip_len;
	unsigned short ip_id;
	unsigned short ip_off;
#define	IP_RF 0x8000			
#define	IP_DF 0x4000			
#define	IP_MF 0x2000			
#define	IP_OFFMASK 0x1fff	
	uint8_t ip_ttl;
	uint8_t ip_p;
	unsigned short ip_sum;
	struct in_addr ip_src, ip_dst;
};

ip_t readIpHeader(const uint8_t* data);

enum IpProtocols
{
	IP_ICMP = 1,
	IP_TCP = 6,
	IP_UDP = 17
	//add 
};

std::string strProtInIp(uint8_t prot);

void writeIpHeader(const ip_t& ipHdr);

struct tcp_t
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t data_offset;//4 bits
	uint8_t flags;
#define FIN 0x01;
#define SYN 0x02;
#define RST 0x04;
#define PSH 0x08;
#define ACK 0x10;
#define URG 0x20;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
};


tcp_t readTcpHeader(const uint8_t* data);

std::string strTcpFlags(uint8_t flags);

void writeTcpHeader(const tcp_t& tcpHdr);

struct udp_t
{
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
};

udp_t readUdpHeader(const uint8_t* data);

void writeUdpHeader(const udp_t& udpHdr);

icmphdr readIcmpHeader(const uint8_t* data);

void writeIcmpHeader(const icmphdr& icmpHdr);

class LengthCollector
{
private:
	std::array <int, 6> m_distrib{ 0,0,0,0,0,0 };
public:
	LengthCollector();
	
	~LengthCollector();
	
	void collectLength(int length);
	
	void printDistribution();
	
};

class ProtocolCollector
{
private:
	ether_header* m_ethHdrPtr;
	ip_t* m_ipHdrPtr;
	std::array<int, 5> m_protDistribution = { 0,0,0,0,0 };
	enum  ethernetType
	{
		ETHTYPE_PUP = 0x0200,          /* Xerox PUP */
		ETHTYPE_SPRITE = 0x0500,		/* Sprite */
		ETHTYPE_IP = 0x0800,		/* IP */
		ETHTYPE_ARP = 0x0806,		/* Address resolution */
		ETHTYPE_REVARP = 0x8035,		/* Reverse ARP */
		ETHTYPE_AT = 0x809B,		/* AppleTalk protocol */
		ETHTYPE_AARP = 0x80F3,		/* AppleTalk ARP */
		ETHTYPE_VLAN = 0x8100,		/* IEEE 802.1Q VLAN tagging */
		ETHTYPE_IPX = 0x8137,		/* IPX */
		ETHTYPE_IPV6 = 0x86dd,		/* IP protocol version 6 */
		ETHTYPE_LOOPBACK = 0x9000		/* used to test interfaces */
	};
	enum ipType
	{
		IP_ICMP = 1,
		IP_TCP = 6,
		IP_UDP = 17
	};


public:
	ProtocolCollector();
	
	~ProtocolCollector();
	
	void collectProtocol(const uint8_t* mem);
	
	void printDistribution();
	
};


class TcpFlagsCollector
{
private:
	ether_header* m_ethHdrPtr;
	ip_t* m_ipHdrPtr;
	tcp_t* m_tcpHdrPtr;
	std::vector<int> m_flagDistribution{ 0,0,0,0,0,0 };
	enum  ethernetType
	{
		ETHTYPE_PUP = 0x0200,          /* Xerox PUP */
		ETHTYPE_SPRITE = 0x0500,		/* Sprite */
		ETHTYPE_IP = 0x0800,		/* IP */
		ETHTYPE_ARP = 0x0806,		/* Address resolution */
		ETHTYPE_REVARP = 0x8035,		/* Reverse ARP */
		ETHTYPE_AT = 0x809B,		/* AppleTalk protocol */
		ETHTYPE_AARP = 0x80F3,		/* AppleTalk ARP */
		ETHTYPE_VLAN = 0x8100,		/* IEEE 802.1Q VLAN tagging */
		ETHTYPE_IPX = 0x8137,		/* IPX */
		ETHTYPE_IPV6 = 0x86dd,		/* IP protocol version 6 */
		ETHTYPE_LOOPBACK = 0x9000		/* used to test interfaces */
	};
	enum ipType
	{
		IP_ICMP = 1,
		IP_TCP = 6,
		IP_UDP = 17
	};

	void doDistribution(uint8_t flg)
	{
		std::bitset<8> bitarray = flg;
		if (bitarray[1] && (bitarray.count() == 1)) ++m_flagDistribution[0];//SYN
		if (bitarray[1] && bitarray[4] && (bitarray.count() == 2)) ++m_flagDistribution[1]; //SYN + ACK
		if (bitarray[4] && (bitarray.count() == 1)) ++m_flagDistribution[2]; //ACK
		if (bitarray[0] && bitarray[4] && (bitarray.count() == 2)) ++m_flagDistribution[3]; //FIN + ACK
		if (bitarray[2] && (bitarray.count() == 1)) ++m_flagDistribution[4]; // RST
		if (bitarray[2] && bitarray[4] && (bitarray.count() == 2)) ++m_flagDistribution[5]; //RST + ACK */
	}
	

public:
	TcpFlagsCollector();
	
	~TcpFlagsCollector();
	
	void collectTcpFlags(const uint8_t* mem);
	
	void printDistribution();
	
};

class UniqueValueCollector
{
private:
	ether_header* m_ethHdrPtr;
	ip_t* m_ipHdrPtr;
	tcp_t* m_tcpHdrPtr;
	udp_t* m_udpHdrPtr;
	arphdr* m_arpHdrPtr;
	arpdata* m_arpDataPtr;

	std::vector<uint8_t> m_src_mac;
	std::vector<std::vector<uint8_t>> m_array_src_mac;
	std::vector<uint8_t> m_dst_mac;
	std::vector<std::vector<uint8_t>> m_array_dst_mac;
	std::vector<std::vector<uint8_t>> m_collection_src_mac;
	std::vector<std::vector<uint8_t>> m_collection_dst_mac;

	std::vector<in_addr> m_array_src_ip;
	std::vector<in_addr> m_array_dst_ip;
	std::vector<in_addr> m_collection_src_ip;
	std::vector<in_addr> m_collection_dst_ip;

	std::vector<uint16_t> m_array_src_port;
	std::vector<uint16_t> m_array_dst_port;
	std::vector<uint16_t> m_collection_src_port;
	std::vector<uint16_t> m_collection_dst_port;

	enum  ethernetType
	{
		ETHTYPE_PUP = 0x0200,          /* Xerox PUP */
		ETHTYPE_SPRITE = 0x0500,		/* Sprite */
		ETHTYPE_IP = 0x0800,		/* IP */
		ETHTYPE_ARP = 0x0806,		/* Address resolution */
		ETHTYPE_REVARP = 0x8035,		/* Reverse ARP */
		ETHTYPE_AT = 0x809B,		/* AppleTalk protocol */
		ETHTYPE_AARP = 0x80F3,		/* AppleTalk ARP */
		ETHTYPE_VLAN = 0x8100,		/* IEEE 802.1Q VLAN tagging */
		ETHTYPE_IPX = 0x8137,		/* IPX */
		ETHTYPE_IPV6 = 0x86dd,		/* IP protocol version 6 */
		ETHTYPE_LOOPBACK = 0x9000		/* used to test interfaces */
	};
	enum ipType
	{
		IP_ICMP = 1,
		IP_TCP = 6,
		IP_UDP = 17
	};

	bool equal(const std::vector<uint8_t>& mac1, const std::vector<uint8_t>& mac2)
	{
		for (int i = 0; i < 6; ++i)
		{
			if (mac1[i] != mac2[i]) return false;
		}
		return true;
	}

	bool found(const std::vector<uint8_t>& mac_value, const std::vector<std::vector<uint8_t>>& array_mac)
	{
		for (auto const& mac_addr : array_mac)
		{
			if (equal(mac_value, mac_addr)) return true;
		}
		return false;
	}

	std::vector<std::vector<uint8_t>> formCollection(const std::vector<std::vector<uint8_t>>& array_mac)
	{
		std::vector<std::vector<uint8_t>> collection;
		for (auto const& elem : array_mac)
		{
			if (!found(elem, collection)) collection.push_back(elem);
		}
		return collection;
	}

	bool found(const in_addr& ip, const std::vector<in_addr>& array_ip)
	{
		for (auto const& elem : array_ip)
		{
			if (ip.s_addr == elem.s_addr) return true;
		}
		return false;
	}

	std::vector<in_addr> formCollection(const std::vector<in_addr>& array_ip)
	{
		std::vector<in_addr> collection;
		for (auto const& elem : array_ip)
		{
			if (!found(elem, collection)) collection.push_back(elem);
		}
		return collection;
	}

	bool found(const uint16_t& port, const std::vector<uint16_t>& array_port)
	{
		for (auto const& elem : array_port)
		{
			if (port == elem) return true;
		}
		return false;
	}

	std::vector<uint16_t> formCollection(const std::vector<uint16_t>& array_port)
	{
		std::vector<uint16_t> collection;
		for (auto const& elem : array_port)
		{
			if (!found(elem, collection)) collection.push_back(elem);
		}
		return collection;
	}

public:
	UniqueValueCollector();

	~UniqueValueCollector();
	
	void collectInfo(const uint8_t* mem);
	
	void printSrcMacs();
	
	void printDstMacs();
	
	void printSrcCollectionMac();

	void printDstCollectionMac();
	
	void printSrcIps();
	
	void printDstIps();
	
	void printSrcCollectionIps();
	
	void printDstCollectionIps();
	
	void printSrcPorts();
	
	void printDstPorts();
	
	void printSrcCollectionPorts();
	
	void printDstCollectionPorts();
	
	void printNumberOfUniqueValues();
	
};


#endif
