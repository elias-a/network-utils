#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "network.h"

#define MAX_PACKET_SIZE 65535

short isIcmpPacket(struct IpHeader *ipHeader);
short isRequest(struct IpHeader *ipHeader, char *ipAddress);

int main(int argc, char **argv) {
	struct pcap_pkthdr header;
	char errorBuffer[PCAP_ERRBUF_SIZE];
	pcap_t *pcapHandle;
	pcap_if_t *interfaces;

	// The ICMP packet includes an ethernet header, an IP header, and the ICMP message.
	int packetSize = sizeof(struct EtherHeader) + sizeof(struct IpHeader) + sizeof(struct Icmp);

	int maxPacketCount = 2;
	if (argc > 1) {
		maxPacketCount = atoi(argv[1]);
	}

	// Find all network devices.
	if (pcap_findalldevs(&interfaces, errorBuffer) != 0) {
		printf("Error in pcap_findalldevs: %s\n", errorBuffer);
		return 1;
	}

	if (interfaces == NULL) {
		printf("No network devices found");
		return 1;
	}

	// Select the first interface from the list.
	char *interface = interfaces->name;

	int fileDescriptor;
	struct ifreq ifr;

	// Returns a file descriptor for a datagram socket.
	fileDescriptor = socket(AF_INET, SOCK_DGRAM, 0);

	// Set the protocol family to IPv4.
	ifr.ifr_addr.sa_family = AF_INET;

	// Copy the interface name into the name field of 
	// the ifreq struct.
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	// Get the IP address of the network device.
	ioctl(fileDescriptor, SIOCGIFADDR, &ifr);

	close(fileDescriptor);

	// Extract the IP address.
	char *extractedIpAddress = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	char *ipAddress = malloc(strlen(extractedIpAddress));
	memcpy(ipAddress, extractedIpAddress, strlen(extractedIpAddress));

	printf("Interface: %s\nIP Address: %s\n", interface, ipAddress);

	int timeout_ms = 30;
	pcapHandle = pcap_open_live(interface, MAX_PACKET_SIZE, 1, timeout_ms, errorBuffer);
	if (pcapHandle == NULL) {
		printf("Error in pcap_open_live: %s\n", errorBuffer);
		return 1;
	}

	// Read packets until `maxPacketCount` ICMP packets are found.
	int icmpPacketCount = 0;
	while (icmpPacketCount < maxPacketCount) {
		// Read in a packet.
		const unsigned char *packet = pcap_next(pcapHandle, &header);
		if (packet == NULL) {
			continue;
		}

		// Construct pointers to the ethernet header, the IP header,
		// and the ICMP message.
		struct EtherHeader *etherHeader = (struct EtherHeader *)packet;
		struct IpHeader *ipHeader = (struct IpHeader *)(packet + ETHER_HDR_LEN);
		struct Icmp *icmpMessage = (struct Icmp *)(packet + ETHER_HDR_LEN + sizeof(struct IpHeader)); 

		// If the packet is an ICMP message with the specified IP 
		// address as the destination, print the headers and message.
		if (isIcmpPacket(ipHeader) && isRequest(ipHeader, ipAddress)) {
			printEtherHeader(etherHeader);
			printIpHeader(ipHeader);
			printIcmpMessage(icmpMessage);

			icmpPacketCount++;
		}
	}

	free(ipAddress);
	pcap_freealldevs(interfaces);
	pcap_close(pcapHandle);

	return 0;
}

// Determines if the packet contains an ICMP message.
short isIcmpPacket(struct IpHeader *ipHeader) {
	// Protocol 1 corresponds to ICMP.
	if (ipHeader->proto == 1) {
		return 1;
	} else {
		return 0;
	}
}

// Determines if the specified IP address is the 
// destination of the packet.
short isRequest(struct IpHeader *ipHeader, char *ipAddress) {
	if (strcmp(ipAddress, inet_ntoa(ipHeader->dest)) == 0) {
		return 1;
	} else {
		return 0;
	}
}
