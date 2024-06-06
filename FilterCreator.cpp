/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Implementation file for FilterCreator class
 * @Author Marek Effenberger
 * @file FilterCreator.cpp
 */

#include "FilterCreator.h"


std::string FilterCreator::createFilter(const Parser& parser){
    std::string filter = "";

    if (parser.getTcp() || parser.getUdp()) {

        if (parser.getPortSource() != -1) {
            if (parser.getTcp()) {
                filter += "tcp src port " + std::to_string(parser.getPortSource()) + " or ";
            }
            if (parser.getUdp()) {
                filter += "udp src port " + std::to_string(parser.getPortSource()) + " or ";
            }
        }

        if (parser.getPortDestination() != -1) {
            if (parser.getTcp()) {
                filter += "tcp dst port " + std::to_string(parser.getPortDestination()) + " or ";
            }
            if (parser.getUdp()) {
                filter += "udp dst port " + std::to_string(parser.getPortDestination()) + " or ";
            }
        }

        if (parser.getPortSource() == -1 && parser.getPortDestination() == -1) {
            if (parser.getTcp()) {
                filter += "tcp or ";
            }
            if (parser.getUdp()) {
                filter += "udp or ";
            }
        }
    }

    // add all the possible protocols
    if (parser.getIcmp4()) {
        filter += "icmp or ";
    }
    // inspired by https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
    if (parser.getIcmp6()) {
        filter += "(icmp6 and (icmp6[0] == 128 or icmp6[0] == 129)) or ";
    }
    if (parser.getArp()) {
        filter += "arp or ";
    }
    if (parser.getIgmp()) {
        filter += "igmp or ";
    }
    if (parser.getMld()) {
        filter += "(icmp6 and (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132)) or ";
    }
    if (parser.getNdp()) {
        filter += "(icmp6 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137)) or ";
    }

    // if filter is empty, then filter is all the types, delete the last " or " and return the filter
    if (filter.empty()) {
        return "tcp or udp or icmp or arp or igmp or (icmp6 and (icmp6[0] == 128 or icmp6[0] == 129 or icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137 or icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132))";
    } else {
        return filter.substr(0, filter.size() - 4);
    }
}