/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Header file for Utils class
 * @Author Marek Effenberger
 * @file Utils.h
 */

#ifndef IPK_2_UTILS_H
#define IPK_2_UTILS_H

#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <cctype>
#include <netinet/ether.h>
#include <iostream>
#include <pcap/pcap.h>

/**
 * Class that provides utility functions
 */
class Utils {

public:

    /**
     * Formats the given MAC address
     * @param addr
     * @return formatted MAC address
     */
    static std::string formatMAC(const struct ether_addr* addr);

    /**
     * Prints the data of the packet in the offset, hex and ASCII format
     * @param data
     * @param size
     */
    static void printPacketData(const u_char *data, int size);

    /**
     * Converts the given timestamp to a string in the rfc3339 format
     * @param timestamp
     * @return timestamp in rfc3339 format
     */
    static std::string getTimeStamp(const struct pcap_pkthdr* pkthdr);

private:

    /**
     * Converts the given byte to a hex string
     * @param byte
     * @return hex string
     */
    static std::string byteToHex(unsigned char byte);
};


#endif //IPK_2_UTILS_H
