#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

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

void macAddressToString(unsigned char *addr, char *addrStr, int addrSize) {
    int i;
    char *strTemp = malloc(1);

    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        if (i != ETHER_ADDR_LEN - 1) {
            sprintf(strTemp, "%02x-", addr[i]);
            strcat(addrStr, strTemp);
        } else {
            sprintf(strTemp, "%02x", addr[i]);
            strcat(addrStr, strTemp);
        }
    }

    addrStr[addrSize - 1] = '\0';

	free(strTemp);
}

void printEtherHeader(struct EtherHeader *etherHeader) {
	char *src;
	char *dest;
	int i;
	int numSep = 5;
	int strSize = (2 * ETHER_ADDR_LEN) + numSep + 1;

	src = malloc(strSize);
	memset(src, 0, strSize);
	macAddressToString(etherHeader->src, src, strSize);
	dest = malloc(strSize);
	memset(dest, 0, strSize);
	macAddressToString(etherHeader->dest, dest, strSize);

	printf("\nEthernet Header\n");
	printf("\tType: %04x\n", ntohs(etherHeader->type));
	printf("\tSource address: %s\n", src);
	printf("\tDestination address: %s\n", dest);

	free(src);
	free(dest);
}

void printIpHeader(struct IpHeader *ipHeader) {
	printf("IP Header\n");
	printf("\tVersion: %d\n", IP_V(ipHeader));
	printf("\tHeader length: %d\n", IP_HL(ipHeader));
	printf("\tType of service: %d\n", ipHeader->tos);
	printf("\tTotal length: %d\n", ipHeader->len);
	printf("\tID: %d / %04x\n", ipHeader->id, ipHeader->id);
	printf("\tFlags and fragment offset: %d\n", ipHeader->fragmentOffset);
	printf("\tTime to live: %d\n", ipHeader->ttl);
	printf("\tProtocol: %d\n", ipHeader->proto);
	printf("\tChecksum: %04x\n", ntohs(ipHeader->sum));
	printf("\tSource address: %s\n", inet_ntoa(ipHeader->src));
	printf("\tDestination address: %s\n", inet_ntoa(ipHeader->dest));
}

void printIcmpMessage(struct Icmp *icmp) {
	int i;

	printf("ICMP\n");
	printf("\tType: %d\n", icmp->icmpHeader.type);
	printf("\tCode: %d\n", icmp->icmpHeader.code);
	printf("\tChecksum: %d / %04x\n", ntohs(icmp->icmpHeader.sum), ntohs(icmp->icmpHeader.sum));
	printf("\tIdentifier: %d\n", icmp->icmpHeader.iden);
	printf("\tSequence: %d\n", icmp->icmpHeader.seq);
	printf("\tData: ");
	for (i = 0; i < 32; i++) {
    	printf("%x", icmp->data[i]);
	}
	printf("\n");
}
