/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Implementation file for Utils class
 * @Author Marek Effenberger
 * @file Utils.cpp
 */

#include "Utils.h"


std::string Utils::byteToHex(unsigned char byte) {
    std::ostringstream oss;
    oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    return oss.str();
}

void Utils::printPacketData(const u_char *data, int size) {

    std::ostringstream hexStream;
    std::ostringstream asciiStream;

    for (int i = 0; i < size; ++i) {
        // Start of a new line
        if (i % 16 == 0) {
            // Print the previous line if it exists
            if (i != 0) {
                std::cout << "  " << asciiStream.str() << std::endl;
                hexStream.str(""); // Clear the stream
                asciiStream.str(""); // Clear the stream
            }
            // Print the byte offset
            std::cout << "0x" << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
        }

        // Process hex representation
        hexStream << byteToHex(data[i]) << ' ';

        // Process ASCII representation
        asciiStream << (std::isprint(data[i]) ? static_cast<char>(data[i]) : '.');

        // End of a line or end of the packet
        if (i % 16 == 15 || i == size - 1) {
            // If end of packet, ensuring hexStream is aligned properly
            // Count the number of bytes in the last line
            int remainingBytes = (i % 16) + 1;
            std::string alignment = " ";
            // If the last line is not full, adding spaces to align the ASCII representation, three spaces for each byte + one space
            for (int j = 0; j < 3 * (16 - remainingBytes); ++j) {
                alignment += " ";
            }

            std::cout << hexStream.str() << alignment << asciiStream.str();
            hexStream.str(""); // Clear the stream
            asciiStream.str(""); // Clear the stream
        }
    }
    std::cout << std::dec << std::endl; // Ensure the stream is back to decimal
}

std::string Utils::getTimeStamp(const struct pcap_pkthdr* pkthdr) {

    // get the timestamp from the ethernet header
    std::time_t timestamp = pkthdr->ts.tv_sec;
    struct tm* timeInfo = std::localtime(&timestamp);

    char buffer[100];

    // Firstly, set the time in the format of rfc3339 without the ms and timezone
    std::strftime(buffer, 100, "%Y-%m-%dT%H:%M:%S", timeInfo);

    // get the milliseconds
    int milliseconds = pkthdr->ts.tv_usec / 1000;

    // get the timezone
    char timeZone[10];
    // format it in the format of +hh:mm
    std::strftime(timeZone, 10, "%z", timeInfo);
    std::string convertedTimezone = std::string(timeZone).substr(0, 3) + ":" + std::string(timeZone).substr(3, 2);

    // create the final string appended with the milliseconds and the timezone, miliseconds are always 3 digits
    // timezone is converted, but miliseconds are mostly 2 digits, so setw sets is to three digits and if it is 2 digits, it will be filled with 0
    std::ostringstream oss;
    oss << std::string(buffer) << "." << std::setfill('0') << std::setw(3) << milliseconds << convertedTimezone;

    return oss.str();
}

// format the MAC address to the format of xx:xx:xx:xx:xx:xx
// based on https://stackoverflow.com/questions/4587653/output-format-for-mac-address-c-stringstream
std::string Utils::formatMAC(const struct ether_addr* addr) {
    char buffer[18];
    snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)addr->ether_addr_octet[0],
             (unsigned char)addr->ether_addr_octet[1],
             (unsigned char)addr->ether_addr_octet[2],
             (unsigned char)addr->ether_addr_octet[3],
             (unsigned char)addr->ether_addr_octet[4],
             (unsigned char)addr->ether_addr_octet[5]);
    return std::string(buffer);
}