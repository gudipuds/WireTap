#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <time.h>
#include <map>

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>


#include "wt_setup.h"

//Maximum size of a file name
#define MAX_FILE_NAME 1024

//Size of a single word is 4 bytes
#define WORD_SIZE 4

//A single octet takes 2 bytes to represent in a char array
#define OCTET_SIZE 2

//Size of buffer to hold the date and time value
#define BUFF_SIZE 64

//Size of char array to store name of network layer protocol
#define NWPROTOCOL 10

//Size of char array to store name of tcp options
#define TCP_OPT_SIZE 15

//Size of ARP Header
#define ARP_HSIZE 8

//Minimum size of an ip header
#define IP_HSIZE 20

//Minimum size of an tcp header
#define TCP_HSIZE 20

//Minimum size of an udp header
#define UDP_HSIZE 20

//Size of ICMP Header
#define ICMP_HSIZE 8

using namespace std;

//Modifying the structure of ARP header to get the Ethernet address and ip address
struct arpheader
  {
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
#if 1
    unsigned char ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char ar_sip[4];		/* Sender IP address.  */
    unsigned char ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char ar_tip[4];		/* Target IP address.  */
#endif
};

//A structure to store the summary of all packets
struct packetSummary {
  int packetCounter;
  int brokenPackCounter;
  int minPackSize;
  int maxPackSize;
  int totalPacketsSize;
  long startTime;
  long endTime;
  struct timeval tv;
} packSummary;

struct tcp_options {
  uint8_t kind;
  uint8_t length;
};

//Declaring maps to store the header value and their respective counts
map<string, int> NLProtocol;
map<string, int> TLProtocol;
map<string, int> srcEthAddrList;
map<string, int> destEthAddrList;
map<string, int> destIPAddrList;
map<string, int> srcIPAddrList;
map<string, int> arpParticipants;
map<string, int> tcpFlagsList;
map<string, int> tcpOptionsList;
map<int, int> srcTCPPortsList;
map<int, int> destTCPPortsList;
map<int, int> srcUDPPortsList;
map<int, int> destUDPPortsList;
map<int, int> ICMPTypesList;
map<int, int> ICMPCodesList;

/**
 * getReadableHostAddress(unsigned char * addr, int addrLen, char delimiter) -> void
 *
 * Converts the non readable host address (Ethernet/IP) to readable format
 * addrLen is 4 for IP, 6 for Ethernet address
 * delimiter is . for IP, : for Ethernet address
 **/

void getReadableHostAddress(char * readableAddress, unsigned char * addr, int addrLen, char delimiter) {
  char addrOctet[OCTET_SIZE];

  //Read octet by octet and store it in a temporary buffer
  for (int i = 0; i < addrLen; i++) {
    sprintf(addrOctet, "%02x%c", addr[i], delimiter);
	strcat(readableAddress, addrOctet);
  }
  readableAddress[(addrLen * 3) - 1] = '\0';
}


/**
 * isTcpflagsListEmpty() -> void
 *
 * Checks if the tcpFlagsList has all options values equal to 0
 **/
bool isTcpflagsListEmpty() {
    if (tcpFlagsList["ACK"] == 0 && tcpFlagsList["FIN"] == 0 && tcpFlagsList["PSH"] == 0
        && tcpFlagsList["RST"] == 0 && tcpFlagsList["SYN"] == 0 && tcpFlagsList["URG"] == 0)
        return true;
    else 
	  return false;		
}

/**
 * getICMPHeaders(const u_char * packet) -> void
 *
 * Gets the ICMP headers from an IP packet
 **/

void getICMPHeaders(const u_char * packet) {
  map<int, int>::iterator it;

  if (packet + UDP_HSIZE != '\0') {
    //Get the ICMP header from the packet
    struct icmphdr *icmpPacket = (struct icmphdr *)packet ;

    //Get ICMP types and store it in a map
    it = ICMPTypesList.find(icmpPacket->type);
    if (it != ICMPTypesList.end()) {
      ICMPTypesList[icmpPacket->type]++;
    }
    else {
      ICMPTypesList[icmpPacket->type] = 1;
    }

    //Get ICMP codes and store it in a map	
	it = ICMPCodesList.find(ntohs(icmpPacket->code) );
    if (it != ICMPCodesList.end()) {
      ICMPCodesList[ntohs(icmpPacket->code)]++;
    }
    else {
      ICMPCodesList[ntohs(icmpPacket->code)] = 1;
    }
  }
  else
    packSummary.brokenPackCounter++;
}

/**
 * getUDPHeaders(const u_char * packet) -> void
 *
 * Gets the UDP headers from an IP packet
 **/

void getUDPHeaders(const u_char * packet) {
  map<int, int>::iterator it;

  if (packet + UDP_HSIZE != '\0') {
    //Get the UDP header from the packet
    struct udphdr *udp =(struct udphdr *)packet;

    //Store the source UDP ports in a Map
    it = srcUDPPortsList.find(ntohs(udp->source) );
    if (it != srcUDPPortsList.end()) {
      srcUDPPortsList[ntohs(udp->source)]++;
    }
    else {
      srcUDPPortsList[ntohs(udp->source)] = 1;
    }

    //Store the destination UDP ports in a Map
    it = destUDPPortsList.find(ntohs(udp->dest));
    if (it != destUDPPortsList.end()) {
      destUDPPortsList[ntohs(udp->dest)]++;
    }
    else {
      destUDPPortsList[ntohs(udp->dest)] = 1;
    }
  }
  else
    packSummary.brokenPackCounter++;
}

/**
 * getTCPHeaders(const u_char * packet) -> void
 *
 * Gets the TCP headers from an IP packet
 **/

void getTCPHeaders(const u_char * packet) {
  char tcpOptions[TCP_OPT_SIZE], optLen[WORD_SIZE];
  int optionsIndex = 0, optionsLength;
  bool tcpOneOption;
  unsigned short kind;
  unsigned short length;
  map<int, int>::iterator it;
  map<string, int>::iterator optIt;

  if ( packet + TCP_HSIZE != '\0') {
    //Get TCP header from the packet
    struct tcphdr *tcp = ( struct tcphdr *)packet;

    //Store the source TCP ports in a Map
    it = srcTCPPortsList.find(ntohs(tcp->source) );
    if (it != srcTCPPortsList.end()) {
      srcTCPPortsList[ntohs(tcp->source)]++;
    }
    else {
      srcTCPPortsList[ntohs(tcp->source)] = 1;
    }

    //Store the destination TCP ports in a Map
    it = destTCPPortsList.find(ntohs(tcp->dest));
    if (it != destTCPPortsList.end()) {
      destTCPPortsList[ntohs(tcp->dest)]++;
    }
    else {
      destTCPPortsList[ntohs(tcp->dest)] = 1;
    }

	//Check for TCP flags and store them in a map
	if(tcp->ack)
      tcpFlagsList["ACK"]++;
    if(tcp->fin)
      tcpFlagsList["FIN"]++;
	if(tcp->psh)
      tcpFlagsList["PSH"]++;
	if(tcp-> rst)
      tcpFlagsList["RST"]++;  
	if(tcp->syn)      
      tcpFlagsList["SYN"]++;  
    if(tcp->urg)      
      tcpFlagsList["URG"]++;

	//Check if the TCP header has any options
	if ((TCP_HSIZE/WORD_SIZE != tcp->doff) && (packet + tcp->doff != '\0')) {
	  tcpOneOption = false;
	  optionsIndex = TCP_HSIZE;
	  optionsLength = tcp->doff * WORD_SIZE;

	  while(optionsIndex < optionsLength) {
	    kind = packet[optionsIndex];

		//Store the TCP options in a map
        sprintf(tcpOptions,"%d (0x%d)", kind, kind);
		optIt = tcpOptionsList.find(tcpOptions);
	    if (optIt != tcpOptionsList.end())
	      tcpOptionsList[tcpOptions]++;
	    else
	      tcpOptionsList[tcpOptions] = 1;

		//Do the appropriate action based on kind value
		//Kind = 0 means End of Tcp Options list
		if (kind == 0) {
		  tcpOptionsList.erase(tcpOptions);
		  break;
		}
		//If kind = 1, next option is in the immediate byte i.e., length = 0
		else if (kind == 1) {
		  optionsIndex ++;
		  if (tcpOneOption)
		    tcpOptionsList[tcpOptions]--;
		  tcpOneOption = true;
		}
		//For all other TCP options, move the optionsIndex by length value
		else {
		  length = packet[optionsIndex + 1];
		  sprintf(optLen, "%d", packet[optionsIndex + 1]);
		  optionsIndex += length;
		}
	  }
	}
	else
	  packSummary.brokenPackCounter++;
  }
  else
    packSummary.brokenPackCounter++;
}

/**
 * getIPHeaders(const u_char * packet) -> void
 *
 * Gets the IP headers for an IP packet
 **/

void getIPHeaders(const u_char * packet) {
  char srcIPAddr[INET_ADDRSTRLEN], destIPAddr[INET_ADDRSTRLEN], TLProto[OCTET_SIZE];
  struct in_addr addr;
  map<string, int>::iterator it;

  if ( packet + IP_HSIZE != '\0') {
    //Get IP header from the packet
    struct iphdr *ip = (struct iphdr *)(packet);

    //Convert the Source ip address to readable format
    srcIPAddr[0] = '\0';
    addr.s_addr= ip->saddr;
    inet_ntop(AF_INET, &(addr.s_addr), srcIPAddr, INET_ADDRSTRLEN);
    string srcIPAddrs(srcIPAddr);

    //Store the source IP Address in a Map
    it = srcIPAddrList.find(srcIPAddrs);
    if (it != srcIPAddrList.end()) {
      srcIPAddrList[srcIPAddrs]++;
    }
    else {
      srcIPAddrList[srcIPAddrs] = 1;
    }

    //Convert the Destination IP address to readable format
    addr.s_addr= ip->daddr;
    inet_ntop(AF_INET, &(addr.s_addr), destIPAddr, INET_ADDRSTRLEN);  
    string destIPAddrs(destIPAddr);

    //Store the destination IP Address in a Map
    it = destIPAddrList.find(destIPAddrs);
    if (it != destIPAddrList.end()) {
      destIPAddrList[destIPAddrs]++;
    }
    else {
      destIPAddrList[destIPAddrs] = 1;
    }

    //Get transport layer protocol from ip packet
    switch(ip->protocol){
	  //Check for a TCP protocol
      case IPPROTO_TCP:
	    it = TLProtocol.find("TCP");
	    if (it != TLProtocol.end())
	      TLProtocol["TCP"]++;
	    else
	      TLProtocol["TCP"] = 1;
	    getTCPHeaders( packet + ip->ihl* 4) ;
 	    break;

	  //Check for an UDP protocol
	  case IPPROTO_UDP:
	    it = TLProtocol.find("UDP");
	    if (it != TLProtocol.end())
	      TLProtocol["UDP"]++;
	    else
	      TLProtocol["UDP"] = 1;
	    getUDPHeaders( packet + ip->ihl * 4);
	    break;

	  //Check for an ICMP protocol
	  case IPPROTO_ICMP:
	    it = TLProtocol.find("ICMP");
	    if (it != TLProtocol.end())
	      TLProtocol["ICMP"]++;
	    else
	      TLProtocol["ICMP"] = 1;
	    getICMPHeaders( packet + ip->ihl * 4);
	    break;

      //Check for other transport layer protocols
	  default:
	    sprintf(TLProto, "%d", ip->protocol);
	    it = TLProtocol.find(TLProto);
	    if (it != TLProtocol.end())
	      TLProtocol[TLProto]++;
	    else
	      TLProtocol[TLProto] = 1;
	    break;
    }
  }
  else
    packSummary.brokenPackCounter++;
}

/**
 * getARPHeaders(const u_char * packet) -> void
 *
 * Gets the ARP headers for an ARP packet
 **/

void getARPHeaders(const u_char * packet) {
  char arpEthAddr[ETH_ALEN * 3], arpIpAddr[INET_ADDRSTRLEN], addrOctet[OCTET_SIZE * 2];
  map<string, int>::iterator it;

  //Check for a broken packet
  if (packet + ARP_HSIZE != '\0') {
    //Get ARP header from the packet
    struct arpheader *a = (struct arpheader *)(packet);

    //Convert the ARP source Ethernet address to readable format
    arpEthAddr[0] = '\0';
    getReadableHostAddress(arpEthAddr, a->ar_sha, ETH_ALEN, ':');
    string arpEthAddrs(arpEthAddr);

    //Get source ip addr from ARP header
    arpIpAddr[0] = '\0';
    for (int i = 0; i < 4; i++) {
	    sprintf(addrOctet, "%d", a->ar_sip[i]);
	  if (i != 3)
	    strcat(addrOctet, ".");
	  strcat(arpIpAddr, addrOctet);
    }
    string arpIPAddrs(arpIpAddr);

    //Append ip address to the Ethernet address
    arpEthAddrs += " \\ " + arpIPAddrs;

    //Store the source Ethernet Address in a Map
    it = arpParticipants.find(arpEthAddrs);
    if (it != arpParticipants.end()) {
      arpParticipants[arpEthAddrs]++;
    }
    else {
      arpParticipants[arpEthAddrs] = 1;
    }
  }
  else
    packSummary.brokenPackCounter++;
}

/**
 * getLinkLayerHeaders(const u_char * packet) -> void
 *
 * Gets the link layer headers and calls another function to parse network layer headers.
 **/

void getLinkLayerHeaders(const u_char * packet) {
  char srcEthAddr[ETH_ALEN * 3], destEthAddr[ETH_ALEN * 3], proto[NWPROTOCOL];
  map<string, int>::iterator it;

  //Check if the packet is not broken
  if ( packet + ETH_HLEN != '\0') {
    //Get Ethernet header from the packet
    struct ethhdr *e = (struct ethhdr *)(packet);

    //Convert the Source Ethernet address to readable format
    srcEthAddr[0] = '\0';
    getReadableHostAddress(srcEthAddr, e->h_source, ETH_ALEN, ':');
    string srcEthAddrs(srcEthAddr);

    //Store the source Ethernet Address in a Map
    it = srcEthAddrList.find(srcEthAddrs);
    if (it != srcEthAddrList.end()) {
      srcEthAddrList[srcEthAddrs]++;
    }
    else {
      srcEthAddrList[srcEthAddrs] = 1;
    }

    //Convert the Destination Ethernet address to readable format
    destEthAddr[0] = '\0';
    getReadableHostAddress(destEthAddr, e->h_dest, ETH_ALEN, ':');
    string destEthAddrs(destEthAddr);
  
    //Store the destination Ethernet Address in a Map
    it = destEthAddrList.find(destEthAddrs);
    if (it != destEthAddrList.end()) {
      destEthAddrList[destEthAddrs]++;
    }
    else {
      destEthAddrList[destEthAddrs] = 1;
    }

	//Check for IP protocol
    if (ntohs(e->h_proto) == ETH_P_IP) {
      //Adds a value to the map for network layer protocol
      it = NLProtocol.find("IP");
	  if (it != NLProtocol.end())
	    NLProtocol["IP"]++;
	  else
	    NLProtocol["IP"] = 1;

	  //Gets the values from IP headers
	  getIPHeaders(packet + ETH_HLEN);
    }
	//Check for ARP protocol
    else if (ntohs(e->h_proto) == ETH_P_ARP) {
      //Adds a value to the map for network layer protocol
      it = NLProtocol.find("ARP");
	  if (it != NLProtocol.end())
	    NLProtocol["ARP"]++;
	  else
	    NLProtocol["ARP"] = 1;
	
	  //Gets the values from ARP headers
      getARPHeaders(packet + ETH_HLEN);
    }
	//Check for other protocols
    else {
      sprintf(proto, "%u (0x%02x)", ntohs(e->h_proto), ntohs(e->h_proto));
      it = NLProtocol.find(proto);
	  if (it != NLProtocol.end())
	    NLProtocol[proto]++;
	  else
	    NLProtocol[proto] = 1;
    }
  }
  else
    packSummary.brokenPackCounter++;
}

/**
 * getPacketHeaders(u_char *args,const struct pcap_pkthdr *packet_data,const u_char * packet) -> void
 *
 * Gets the packet headers and calls appropriate function for every packet.
 **/

void getPacketHeaders(u_char *args,const struct pcap_pkthdr *packet_data,const u_char * packet){
  //Increment the packet counter
  packSummary.packetCounter++;

  //Get the running length of all packets
  packSummary.totalPacketsSize += packet_data->len;

  if (packSummary.packetCounter == 1) {
    //Initialise maximum, minimum packet sizes to the packet length for first packet
    packSummary.minPackSize = packet_data->len;
	packSummary.maxPackSize = packet_data->len;

	//Get the time stamp of first packet
	packSummary.startTime = packet_data->ts.tv_sec;
	packSummary.tv = packet_data->ts;
  }
  else {
    //Get the time stamp for rest all packets, endTime will finally store the time stamp value of last packet
    packSummary.endTime = packet_data->ts.tv_sec;

	//Update the minimum and maximum packet sizes
    if (packet_data->len < packSummary.minPackSize)
	  packSummary.minPackSize = packet_data->len;
	else if (packet_data->len > packSummary.maxPackSize)
	  packSummary.maxPackSize = packet_data->len;
  }

  //Get link layer header values
  if (packet_data->caplen <= packet_data->caplen)
    getLinkLayerHeaders(packet);  
}

/**
 * printPacketDetails() -> void
 *
 * Prints the summary of analysed packets to output screen
 **/

void printPacketDetails() {
  time_t nowtime;
  struct tm *nwtm;
  char timeBuf[BUFF_SIZE];
  int capDuration = packSummary.endTime - packSummary.startTime;

  if (capDuration < 0)
    capDuration = 0;

  //Get the time of date of first packet captured (#Reference - http://stackoverflow.com/questions/2408976/struct-timeval-to-printable-format)
  nowtime = packSummary.tv.tv_sec;
  nwtm = localtime(&nowtime);
  strftime(timeBuf, sizeof timeBuf, "%Y-%m-%d %H:%M:%S", nwtm);

  printf("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n\n");

  //Prints PACKET CAPTURE summary
  printf("=========Packet capture summary=========\n\n");
  printf("Capture start date:\t%s EDT\n", timeBuf);
  printf("Capture duration:\t%ld\n", capDuration);
  printf("Packets in capture:\t%d\n", packSummary.packetCounter);
  printf("Minimum packet size:\t%d\n", packSummary.minPackSize);
  printf("Maximum packet size:\t%d\n", packSummary.maxPackSize);
  printf("Average packet size:\t%.2f\n\n\n", (float)packSummary.totalPacketsSize/packSummary.packetCounter);
  /*if (packSummary.brokenPackCounter > 0)
    printf("Number of broken packets:\t%d\n\n\n", packSummary.brokenPackCounter);*/

  //Prints the LINK LAYER summary
  printf("=========Link layer=========\n\n");

  //Prints the Source Ethernet Address summary
  printf("---------Source Ethernet Addresses---------\n\n");
  if(!srcEthAddrList.empty()) {
    for (map<string,int>::iterator it = srcEthAddrList.begin(); it != srcEthAddrList.end(); ++it)
      cout << it->first << "  \t\t " << it->second << endl;
    printf("\n");
  }
  else
    printf("(no results)\n\n");

  //Prints the Destination Ethernet Address summary
  printf("---------Destination Ethernet Addresses---------\n\n");
  if(!destEthAddrList.empty()) {
    for (map<string,int>::iterator it = destEthAddrList.begin(); it != destEthAddrList.end(); ++it)
      cout << it->first << " \t\t " << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n\n");

  //Prints NETWORK LAYER summary
  printf("=========Network layer=========\n\n");

  //Prints network layers protocols summary
  printf("---------Network layer protocols---------\n\n");
  if(!NLProtocol.empty()) {
    for (map<string,int>::iterator it = NLProtocol.begin(); it != NLProtocol.end(); ++it)
      cout << it->first << "\t\t" << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n");

  //Prints the Source IP address Address summary
  printf("---------Source IP addresses---------\n\n");
  if(!srcIPAddrList.empty()) {
    for (map<string,int>::iterator it = srcIPAddrList.begin(); it != srcIPAddrList.end(); ++it)
      cout << it->first << " \t\t " << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n");

  //Prints the Destination IP Address summary
  printf("---------Destination IP addresses---------\n\n");
  if(!destIPAddrList.empty()) {
    for (map<string,int>::iterator it = destIPAddrList.begin(); it != destIPAddrList.end(); ++it)
      cout << it->first << " \t\t " << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n");

  //Prints arp participants summary
  printf("---------Unique ARP participants---------\n\n");
  if(!arpParticipants.empty()) {
    for (map<string,int>::iterator it = arpParticipants.begin(); it != arpParticipants.end(); ++it)
      cout << it->first << " \t\t " << it->second << endl;
    printf("\n\n\n");
  }
  else
    printf("(no results)\n\n\n");

  //Prints TRANSPORT LAYER summary
  printf("=========Transport layer=========\n\n");

  //Prints transport layers protocols summary
  printf("---------Transport layer protocols---------\n\n");
  if(!TLProtocol.empty()) {
    for (map<string,int>::iterator it = TLProtocol.begin(); it != TLProtocol.end(); ++it)
      cout << it->first << "\t\t" << it->second << endl;
    printf("\n\n\n");
  }
  else
    printf("(no results)\n\n\n");

  //Prints TCP header summary
  printf("=========Transport layer: TCP=========\n\n");

  //Prints TCP source ports summary
  printf("---------Source TCP ports---------\n\n");
  if(!srcTCPPortsList.empty()) {
    for (map<int,int>::iterator it = srcTCPPortsList.begin(); it != srcTCPPortsList.end(); ++it)
      cout << it->first << "\t\t" << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n");

  //Prints TCP destination ports summary
  printf("---------Destination TCP ports---------\n\n");
  if(!destTCPPortsList.empty()) {
    for (map<int,int>::iterator it = destTCPPortsList.begin(); it != destTCPPortsList.end(); ++it)
      cout << it->first << "\t\t" << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n");

  //Print TCP flags summary
  printf("---------TCP flags---------\n\n");
  if(!isTcpflagsListEmpty()) {
    for (map<string,int>::iterator it = tcpFlagsList.begin(); it != tcpFlagsList.end(); ++it)
      cout << it->first << " \t\t " << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n");

  //Print TCP options summary
  printf("---------TCP options---------\n\n");
  if(!tcpOptionsList.empty()) {
    for (map<string,int>::iterator it = tcpOptionsList.begin(); it != tcpOptionsList.end(); ++it)
      cout << it->first << " \t\t " << it->second << endl;
    printf("\n\n\n");
  }
  else
    printf("(no results)\n\n\n");

  //Prints UDP header summary
  printf("=========Transport layer: UDP=========\n\n");

  //Prints UDP source ports summary
  printf("---------Source UDP ports---------\n\n");
  if(!srcUDPPortsList.empty()) {
    for (map<int,int>::iterator it = srcUDPPortsList.begin(); it != srcUDPPortsList.end(); ++it)
      cout << it->first << "\t\t" << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n");

  //Prints UDP destination ports summary
  printf("---------Destination UDP ports---------\n\n");
  if(!destUDPPortsList.empty()) {
    for (map<int,int>::iterator it = destUDPPortsList.begin(); it != destUDPPortsList.end(); ++it)
      cout << it->first << "\t\t" << it->second << endl;
    printf("\n\n\n");
  }
  else
    printf("(no results)\n\n\n");

  //Prints ICMP Header summary
  printf("=========Transport layer: ICMP=========\n\n");

  //Prints ICMP types summary
  printf("---------ICMP types---------\n\n");
  if(!ICMPTypesList.empty()) {
    for (map<int,int>::iterator it = ICMPTypesList.begin(); it != ICMPTypesList.end(); ++it)
      cout << it->first << "\t\t" << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n");

  //Prints ICMP types summary
  printf("---------ICMP codes---------\n\n");
  if(!ICMPCodesList.empty()) {
    for (map<int,int>::iterator it = ICMPCodesList.begin(); it != ICMPCodesList.end(); ++it)
      cout << it->first << "\t\t" << it->second << endl;
    printf("\n\n");
  }
  else
    printf("(no results)\n\n");

  printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
}

int main (int argc, char * argv[]) {
  char captureFile[MAX_FILE_NAME];
  pcap_t *pcapHandle;  
  char errorPcap[PCAP_ERRBUF_SIZE];

  //Parse the input arguments
  parse_args(captureFile, argc, argv);

  //Open pcap file
  pcapHandle = pcap_open_offline(captureFile, errorPcap) ;
  if(pcapHandle == NULL ){
    fprintf(stderr,"Error in reading pcap file: %s \n",errorPcap );
	exit(1);
  }

  //Check if the input packet is from ETHERNET
  if(pcap_datalink(pcapHandle) == DLT_EN10MB) {
    packSummary.packetCounter = 0;
	packSummary.totalPacketsSize = 0;
	packSummary.brokenPackCounter = 0;

    //Initialise TCP flags
	tcpFlagsList["ACK"] = 0;
    tcpFlagsList["FIN"] = 0;
    tcpFlagsList["PSH"] = 0;
    tcpFlagsList["RST"] = 0;
    tcpFlagsList["SYN"] = 0;
    tcpFlagsList["URG"] = 0;

    //Iterate through packets and analyse each of them
    pcap_loop(pcapHandle, 0, getPacketHeaders, NULL);

	//Print packet summary
	printPacketDetails();
  }
  else {
    cout << "***************************************************************" << endl << endl;
	cout << "###### The input pcap file is not captured from ETHERNET ######" << endl << endl;
	cout << "***************************************************************" << endl;
  }

  //Close the pcap file
  pcap_close(pcapHandle);

  return 0;
}