/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Implementation file for Sniffer class
 * @Author Marek Effenberger
 * @file Sniffer.cpp
 */

#include "Sniffer.h"

// initialize the static members
pcap_t* Sniffer::handle = nullptr;
std::atomic<bool> Sniffer::stop = false;

bool Sniffer::setUp() {

    char errbuf[PCAP_ERRBUF_SIZE];
    // get the network and mask for the interface
    if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == -1) {
        std::cerr << "Couldn't get netmask for device " << interface << ": " << errbuf << std::endl;
        return false;
    }

    // the interface shall be always specified
    // open the interface for sniffing
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device " << interface << ": " << errbuf << std::endl;
        return false;
    }
    // specify the handle for ethernet only
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Device doesn't support Ethernet: " << interface << std::endl;
        return false;
    }
    // convert the filter to the bpf program
    if (pcap_compile(handle, &fp, filter.c_str(), 0, mask) < 0) {
        std::cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << std::endl;
        return false;
    }
    // set the compiled filter for the pcap handle
    if (pcap_setfilter(handle, &fp) < 0) {
        std::cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << std::endl;
        return false;
    }
    // If the setup was successful, sniffing can start
    return true;
}

void Sniffer::sniff() {

    // start sniffing
    if (pcap_loop(handle, numberOfPackets, packetHandler::handlePacket, nullptr) == -1) {
        if (stop.load()) {
            std::cout << "Sniffing halted by user." << std::endl;
        } else {
            std::cerr << "Error while sniffing: " << pcap_geterr(handle) << std::endl;
        }
    }
}

void Sniffer::signalHandler(int signal) {
    // If SIGINT is received, set the stop flag and break the loop
    if (signal == SIGINT) {
        std::cout << "SIGINT received, preparing to shut down..." << std::endl;
        stop.store(true); // Set the stop flag
        if (handle) {
            pcap_breakloop(handle); // Tell pcap_loop to terminate
        }
    }
}
