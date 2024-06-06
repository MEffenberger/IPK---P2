/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Implementation file for the main function
 * @Author Marek Effenberger
 * @file Main.cpp
 */


#include <string>
#include <pcap/pcap.h>
#include "Parser.h"
#include "FilterCreator.h"
#include "Sniffer.h"


int main(int argc, char* argv[]) {

    Parser parser;
    parser.parseArguments(argc, argv);
    if (!parser.validateArguments()) {
        return 1;
    }
    std::string filter = FilterCreator::createFilter(parser);
    std::string interface = parser.getInterface();
    int numberOfPackets = parser.getNumberOfPackets();

    Sniffer sniffer(interface, filter, numberOfPackets);
    std::signal(SIGINT, Sniffer::signalHandler);

    if (!sniffer.setUp()) {
        return 1;
    }

    sniffer.sniff();

    return 0;
}

