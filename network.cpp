#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include "network.h"

void macAddressToString(unsigned char *addr, char *addrStr, int addrSize) {
    int i;
    char *strTemp = (char *)malloc(1);

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
	int i;
	int numSep = 5;
	int strSize = (2 * ETHER_ADDR_LEN) + numSep + 1;

	char *src = (char *)malloc(strSize);
	memset(src, 0, strSize);
	macAddressToString(etherHeader->src, src, strSize);
	char *dest = (char *)malloc(strSize);
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
