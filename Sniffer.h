/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Header file for Sniffer class
 * @Author Marek Effenberger
 * @file Sniffer.h
 */

#ifndef IPK_2_SNIFFER_H
#define IPK_2_SNIFFER_H

#include <pcap/pcap.h>
#include <string>
#include <iostream>
#include "PacketHandler.h"
#include <memory>
#include <atomic>
#include <csignal>

/**
 * Class that handles the packet sniffing
 */
class Sniffer {

private:
    // Variables for storing the handle, filter, interface and number of packets
    static pcap_t* handle;
    bpf_program fp{};
    bpf_u_int32 net = 0, mask = 0;
    std::string interface;
    std::string filter;
    int numberOfPackets;

    // Static variable for stopping the sniffing when SIGINT is received
    static std::atomic<bool> stop;

    // Pointer to the packet handler
    packetHandler* packetHandlerPtr;

public:
    // Constructor
    Sniffer(const std::string& interface, const std::string& filter, int numberOfPackets) : interface(interface), filter(filter), numberOfPackets(numberOfPackets) {
        packetHandlerPtr = new packetHandler();
    };

    // Destructor, closes the handle and deletes the packet handler
    ~Sniffer(){
        if (handle) {
            pcap_breakloop(handle); // Ensure no more packets are processed
            pcap_freecode(&fp);
            pcap_close(handle);
            handle = nullptr;
        }
        delete packetHandlerPtr;
    }

    /**
     * Sets up the sniffer, opens the handle, sets the filter and sets the callback function
     * @return true if the setup was successful, false otherwise
     */
    bool setUp();

    /**
     * Starts the sniffing
     */
    void sniff();

    /**
     * Signal handler for SIGINT
     * @param signal
     */
    static void signalHandler(int signal);

};


#endif //IPK_2_SNIFFER_H
