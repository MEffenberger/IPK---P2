/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Implementation file for Parser class
 * @Author Marek Effenberger
 * @file Parser.cpp
 */
#include "Parser.h"


void Parser::parseArguments(int argc, char **argv) {

    int optionIdx = 0;
    int opt;

    while ((opt = getopt_long(argc, argv, shortOptions, longOptions.data(), &optionIdx)) != -1) {
        switch (opt) {
            case 'i':
                if (optarg) {
                    interface = optarg;
                } else if (optind < argc && argv[optind][0] != '-') {
                    interface = argv[optind++];
                } else {
                    printAllInterfaces();
                    exit(0);
                }
                //std::cout << "Sole interface: " << interface << std::endl;
                break;
            case 'p':
                //std::cout << "Setting both ports.." << optarg << std::endl;
                portSource = std::stoi(optarg);
                portDestination = std::stoi(optarg);
                pflag = true;
                //std::cout << "Port source: " << portSource << std::endl;
                //std::cout << "Port destination: " << portDestination << std::endl;
                break;
            case 's':
                //std::cout << "Setting port source.." << optarg << std::endl;
                portSource = std::stoi(optarg);
                psflag = true;
                //std::cout << "Port source: " << portSource << std::endl;
                break;
            case 'd':
                //std::cout << "Setting port destination.. " << optarg << std::endl;
                portDestination = std::stoi(optarg);
                pdflag = true;
                //std::cout << "Port destination: " << portDestination << std::endl;
                break;
            case 't':
                //std::cout << "TCP" << std::endl;
                tcp = true;
                break;
            case 'u':
                //std::cout << "UDP" << std::endl;
                udp = true;
                break;
            case 'n':
                // Check if optarg is a number
                for (int i = 0; optarg[i] != '\0'; i++) {
                    if (!std::isdigit(optarg[i])) {
                        std::cerr << "You have to specify a number!" << std::endl;
                        exit(1);
                    }
                }
                numberOfPackets = std::stoi(optarg);
                //std::cout << "Number of packets: " << numberOfPackets << std::endl;
                break;
            case 'h':
                printHelp();
                exit(0);
            case 0:
                if (strcmp(longOptions[optionIdx].name, "icmp4") == 0) {
                    icmp4 = true;
                    //std::cout << "ICMP4" << std::endl;
                } else if (strcmp(longOptions[optionIdx].name, "icmp6") == 0) {
                    icmp6 = true;
                    //std::cout << "ICMP6" << std::endl;
                } else if (strcmp(longOptions[optionIdx].name, "arp") == 0) {
                    arp = true;
                    //std::cout << "ARP" << std::endl;
                } else if (strcmp(longOptions[optionIdx].name, "ndp") == 0) {
                    ndp = true;
                    //std::cout << "NDP" << std::endl;
                } else if (strcmp(longOptions[optionIdx].name, "igmp") == 0) {
                    igmp = true;
                    //std::cout << "IGMP" << std::endl;
                } else if (strcmp(longOptions[optionIdx].name, "mld") == 0) {
                    mld = true;
                    //std::cout << "MLD" << std::endl;
                }
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " [-i interface] [-p port] [-t] [-u] [-n number]" << std::endl;
                exit(1);
        }
    }
}

void Parser::printAllInterfaces() {
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    // get the list of all interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        exit(1);
    }
    // print them all
    for (dev = alldevs; dev; dev = dev->next) {
        std::cout << dev->name << std::endl;
    }
    // free the list
    pcap_freealldevs(alldevs);
}

bool Parser::validateArguments() {

    //if empty interface and anything else specified, error
    if (interface.empty() && (tcp || udp || icmp4 || icmp6 || arp || ndp || igmp || mld || pflag || psflag || pdflag)) {
        std::cerr << "You have to specify an interface!" << std::endl;
        return false;
    }

    if (pflag && (psflag || pdflag)){
        std::cerr << "You can only specify -p XOR (--port-source OR --port-destination)." << std::endl;
        return false;
    }

    if ((pflag || psflag || pdflag) && !(tcp || udp)) {
        std::cerr << "You have to specify either -t or -u" << std::endl;
        return false;
    }

    return true;
}

std::string Parser::getInterface() const {
    return interface;
}

int Parser::getNumberOfPackets() const {
    return numberOfPackets;
}

bool Parser::getTcp() const {
    return tcp;
}

bool Parser::getUdp() const {
    return udp;
}

bool Parser::getIcmp4() const {
    return icmp4;
}

bool Parser::getIcmp6() const {
    return icmp6;
}

bool Parser::getArp() const {
    return arp;
}

bool Parser::getNdp() const {
    return ndp;
}

bool Parser::getIgmp() const {
    return igmp;
}

bool Parser::getMld() const {
    return mld;
}

int Parser::getPortSource() const {
    return portSource;
}

int Parser::getPortDestination() const {
    return portDestination;
}

void Parser::printHelp() {
    std::cout << "Usage: ./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num} [-h | --help]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -i, --interface <interface>  Interface to sniff on" << std::endl;
    std::cout << "  -p, --port <port>            Port to sniff on" << std::endl;
    std::cout << "  --port-source <port>         Source port to sniff on" << std::endl;
    std::cout << "  --port-destination <port>    Destination port to sniff on" << std::endl;
    std::cout << "  -t, --tcp                    Sniff only TCP packets" << std::endl;
    std::cout << "  -u, --udp                    Sniff only UDP packets" << std::endl;
    std::cout << "  -n, <number>                 Number of packets to sniff" << std::endl;
    std::cout << "  --icmp4                      Sniff only ICMPv4 packets" << std::endl;
    std::cout << "  --icmp6                      Sniff only ICMPv6 packets" << std::endl;
    std::cout << "  --arp                        Sniff only ARP packets" << std::endl;
    std::cout << "  --ndp                        Sniff only NDP packets" << std::endl;
    std::cout << "  --igmp                       Sniff only IGMP packets" << std::endl;
    std::cout << "  --mld                        Sniff only MLD packets" << std::endl;
    std::cout << "  -h, --help                   Display this help message" << std::endl;
}