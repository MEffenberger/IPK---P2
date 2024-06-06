/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Header file for packetHandler class
 * @Author Marek Effenberger
 * @file PacketHandler.h
 */

#ifndef IPK_2_PACKETHANDLER_H
#define IPK_2_PACKETHANDLER_H

#include <pcap/pcap.h>
#include "Utils.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/ip_icmp.h>
#include <cctype>
#include <cstring>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/igmp.h>
#include <netinet/icmp6.h>
#include <iomanip>

/**
 * Class that handles the packet processing
 */
class packetHandler {

public:
    // Constructor and destructor
    packetHandler() = default;

    ~packetHandler() = default;

    /**
     * Handles the packet, calls the appropriate functions based on the protocol
     * @param userData
     * @param pkthdr
     * @param packet
     */
    static void handlePacket(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

private:

    /**
     * Handles the ethernet layer, gets the type of the protocol and calls the appropriate function
     * @param ethernetHeader
     * @param packet
     */
    static void networkLayerSwitch(const struct ether_header* ethernetHeader, const u_char* packet);

    /**
     * Handles the ipv4 protocol
     * @param packet
     */
    static void ipv4Layer(const u_char* packet);

    /**
     * Handles the ipv6 protocol
     * @param packet
     */
    static void ipv6Layer(const u_char* packet);

    /**
     * Handles the arp protocol
     * @param packet
     */
    static void arpLayer(const u_char* packet);
};


#endif //IPK_2_PACKETHANDLER_H
