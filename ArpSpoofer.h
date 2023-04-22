#pragma once

#include <string>
#include <pcap.h>
#include "network.h"

class ArpSpoofer {
    public:
        ArpSpoofer();
        ArpSpoofer(
            std::string,
            std::string,
            std::string,
            std::string,
            std::string,
            int);
        ~ArpSpoofer();
        int initialize();
        static void signalHandler(int);
        int spoof();
    private:
        std::string spoofMac;
        std::string routerMac;
        std::string targetMac;
        std::string routerIp;
        std::string targetIp;
        int maxPacketSize;
        std::string interface;
        pcap_t *pcapHandle;

        void registerSignalHandler();
        void createArpReply(
            struct EtherHeader *,
            struct Arp *,
            u_char *,
            std::string,
            std::string,
            std::string,
            std::string
        );
        void cleanUp(int);
};
