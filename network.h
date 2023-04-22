#pragma once

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
#define ARP_PACKET_SIZE sizeof(struct EtherHeader) + sizeof(struct Arp)

struct EtherHeader {
	uint8_t dest[ETHER_ADDR_LEN];            // Destination MAC address
	uint8_t src[ETHER_ADDR_LEN];             // Source MAC address
	uint16_t type;                           // Type of ethernet packet
} __attribute__((packed));

struct IpHeader {
	uint8_t vhl;                             // Version and header length
#define IP_V(ip) ((ip->vhl & 0xf0) >> 4)     // Retrieves version
#define IP_HL(ip) (ip->vhl & 0x0f)           // Retrieves header length
	uint8_t tos;                             // Type of service
	uint16_t len;                            // Total length
	uint16_t id;                             // ID number
	uint16_t fragmentOffset;                 // Flags and fragment offset 
	uint8_t ttl;                             // Time to live
	uint8_t proto;                           // Protocol type
	uint16_t sum;                            // Checksum
	struct in_addr src;                      // Source IP address
	struct in_addr dest;                     // Destination IP address
} __attribute__((packed));

struct IcmpHeader {
	uint8_t type;                            // 8 for echo request, 0 for echo reply
	uint8_t code;                            // 0
	uint16_t sum;                            // Checksum
	uint16_t iden;                           // 
	uint16_t seq;                            //
} __attribute__((packed));

struct Icmp {
	struct IcmpHeader icmpHeader;
	uint8_t data[32];
} __attribute__((packed));

struct Arp {
  uint16_t h_type;
  uint16_t p_type;
  uint8_t h_addr_len;
  uint8_t p_addr_len;
  uint16_t opcode;
  uint8_t h_src[ETHER_ADDR_LEN];
  struct in_addr p_src;
  uint8_t h_tar[ETHER_ADDR_LEN];
  struct in_addr p_tar;
} __attribute__((packed));

void macAddressToString(unsigned char *, char *, int);
void printEtherHeader(struct EtherHeader *);
void printIpHeader(struct IpHeader *);
void printIcmpMessage(struct Icmp *);
