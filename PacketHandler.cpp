/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Implementation file for packetHandler class
 * @Author Marek Effenberger
 * @file PacketHandler.cpp
 */

#include "PacketHandler.h"

void packetHandler::handlePacket(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    const struct ether_header* ethernetHeader;
    // print the timestamp in rfc3339 format
    std::cout << "timestamp: " << Utils::getTimeStamp(pkthdr) << std::endl;
    //print src MAC address
    ethernetHeader = (struct ether_header*)packet;
    std::cout << "src MAC: " << Utils::formatMAC((struct ether_addr*)ethernetHeader->ether_shost) << std::endl;
    //print dst MAC address
    std::cout << "dst MAC: " << Utils::formatMAC((struct ether_addr*)ethernetHeader->ether_dhost) << std::endl;
    //frame length
    std::cout << "frame length: " << pkthdr->len << " bytes" << std::endl;
    // get the type of the packet

    // switch the type of the packet
    networkLayerSwitch(ethernetHeader, packet);

    std::cout << std::endl;
    Utils::printPacketData((unsigned char*)packet, pkthdr->caplen);
    std::cout << std::endl << std::endl;

    return;

}

void packetHandler::networkLayerSwitch(const struct ether_header* ethernetHeader, const u_char* packet) {

    // get the type of the packet from the ethernet header
    // ntohs is used to convert the network byte order to the host byte order
    u_int16_t type = ntohs(ethernetHeader->ether_type);

    switch (type) {
        case ETHERTYPE_IP: {
            ipv4Layer(packet);
            break;
        }
        case ETHERTYPE_IPV6: {
            ipv6Layer(packet);
            break;
        }
        case ETHERTYPE_ARP: {
            arpLayer(packet);
            break;
        }
    }
    return;
}

void packetHandler::ipv4Layer(const u_char* packet) {

    // get the IP header, it will start after the ethernet header
    const struct ip *ipHeader = (struct ip *) (packet + sizeof(struct ether_header));
    // can use inet_ntoa for the IPv4
    std::cout << "src IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
    std::cout << "dst IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
    // get the protocol from the ip header
    uint8_t protocol = ipHeader->ip_p;

    // IPv4 protocol is specified in 32 bit words, so we need to multiply by 4 to get the correct offset
    // https://stackoverflow.com/questions/11383497/libpcap-payload-offset-66-but-sizeofheaders-doff-62
    // the castings are then done to the correct type
    switch (protocol) {
        case IPPROTO_TCP: {
            std::cout << "TCP Packet" << std::endl;
            const struct tcphdr *tcpHeader = (struct tcphdr *) (packet + sizeof(struct ether_header) +
                                                                ipHeader->ip_hl * 4);
            std::cout << "src port: " << ntohs(tcpHeader->th_sport) << std::endl;
            std::cout << "dst port: " << ntohs(tcpHeader->th_dport) << std::endl;
            break;
        }
        case IPPROTO_UDP: {
            std::cout << "UDP Packet" << std::endl;
            const struct udphdr *udpHeader = (struct udphdr *) (packet + sizeof(struct ether_header) +
                                                                ipHeader->ip_hl * 4);
            std::cout << "src port: " << ntohs(udpHeader->uh_sport) << std::endl;
            std::cout << "dst port: " << ntohs(udpHeader->uh_dport) << std::endl;
            break;
        }
        case IPPROTO_ICMP: {
            std::cout << "ICMP Packet" << std::endl;
            const struct icmphdr *icmpHeader = (struct icmphdr *) (packet + sizeof(struct ether_header) +
                                                                  ipHeader->ip_hl * 4);
            // Additional information on top of the assignment
            // printing the type of the ICMP packet
            std::cout << "ICMP type: " << (int) icmpHeader->type << std::endl;
            break;
        }
        // only for the IPv4 https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol MLD is the IPv6 version
        case IPPROTO_IGMP: {
            std::cout << "IGMP Packet" << std::endl;
            const struct igmp *igmpHeader = (struct igmp *) (packet + sizeof(struct ether_header) +
                                                            ipHeader->ip_hl * 4);
            // Additional information on top of the assignment
            // printing the type of the IGMP packet
            std::cout << "IGMP type: " << (int) igmpHeader->igmp_type << std::endl;
            // printing the group address
            struct in_addr groupAddress;
            memcpy(&groupAddress, &igmpHeader->igmp_group, sizeof(groupAddress));
            std::cout << "Group address: " << inet_ntoa(groupAddress) << std::endl;
            break;
        }
        default: {
            // Should not happen, but if it does, print the protocol
            std::cout << "Protocol: " << (int) protocol << " is unsupported" << std::endl;
            break;
        }
    }
    return;
}

void packetHandler::ipv6Layer(const u_char* packet) {

    // get the IP header, it will start after the ethernet header
    const struct ip6_hdr *ip6Header = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

    // Cannot use inet_ntoa for IPv6, so we need to use inet_ntop
    // https://man7.org/linux/man-pages/man3/inet_ntop.3.html
    char srcIP6[INET6_ADDRSTRLEN];
    char dstIP6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6Header->ip6_src, srcIP6, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6Header->ip6_dst, dstIP6, INET6_ADDRSTRLEN);
    std::cout << "src IP: " << srcIP6 << std::endl;
    std::cout << "dst IP: " << dstIP6 << std::endl;

    // get the protocol from the ip header
    uint8_t protocol = ip6Header->ip6_nxt;
    // IPv6 has fixed value so no need to multiply by 4, the offset is correct
    switch (protocol) {
        case IPPROTO_TCP: {
            std::cout << "TCP Packet" << std::endl;
            const struct tcphdr *tcpHeader = (struct tcphdr *) (packet + sizeof(struct ether_header) +
                                                                sizeof(struct ip6_hdr));
            std::cout << "src port: " << ntohs(tcpHeader->th_sport) << std::endl;
            std::cout << "dst port: " << ntohs(tcpHeader->th_dport) << std::endl;
            break;
        }
        case IPPROTO_UDP: {
            std::cout << "UDP Packet" << std::endl;
            const struct udphdr *udpHeader = (struct udphdr *) (packet + sizeof(struct ether_header) +
                                                                sizeof(struct ip6_hdr));
            std::cout << "src port: " << ntohs(udpHeader->uh_sport) << std::endl;
            std::cout << "dst port: " << ntohs(udpHeader->uh_dport) << std::endl;
            break;
        }
        case IPPROTO_ICMPV6: {
            std::cout << "ICMP6 Packet" << std::endl;
            const struct icmp6_hdr *icmp6Header = (struct icmp6_hdr *) (packet + sizeof(struct ether_header) +
                                                                      sizeof(struct ip6_hdr));

            // Additional information on top of the assignment
            // print the type (echo request, echo reply or ndp or mld)
            int type = icmp6Header->icmp6_type;
            if (type == ICMP6_ECHO_REQUEST) {
                std::cout << "ICMP6 type: Echo request" << std::endl;
            } else if (type == ICMP6_ECHO_REPLY) {
                std::cout << "ICMP6 type: Echo reply" << std::endl;
            } else if (type >= 130 && type <= 132){
                std::cout << "ICMP6 type: MLD" << std::endl;
            } else if (type >= 133 && type <= 137){
                std::cout << "ICMP6 type: NDP" << std::endl;
            }
            break;
        }
        default: {
            std::cout << "Protocol: " << (int) protocol << " is unsupported" << std::endl;
            break;
        }
    }
    return;
}

void packetHandler::arpLayer(const u_char* packet) {

    std::cout << "ARP" << std::endl;
    // get the ARP header
    const struct ether_arp *arpHeader = (struct ether_arp *) (packet + sizeof(struct ether_header));
    struct in_addr srcIP, dstIP;
    memcpy(&srcIP, arpHeader->arp_spa, sizeof(srcIP));
    memcpy(&dstIP, arpHeader->arp_tpa, sizeof(dstIP));
    // The ARP IP addresses are 4 bytes long, so we can use inet_ntoa
    std::cout << "src IP: " << inet_ntoa(srcIP) << std::endl;
    std::cout << "dst IP: " << inet_ntoa(dstIP) << std::endl;
    return;
}
