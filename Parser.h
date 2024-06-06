/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Header file for Parser class
 * @Author Marek Effenberger
 * @file Parser.h
 */

#ifndef IPK_2_PARSER_H
#define IPK_2_PARSER_H

#include <getopt.h>
#include <vector>
#include <string>
#include <iostream>
#include <pcap/pcap.h>
#include <cstring>


/**
 * Class that parses the input arguments, validates them and stores them
 * Utilizes getopt_long function
 */
class Parser {

private:

    // Struct for storing options
    std::vector<option> longOptions = {
            {"interface", no_argument, nullptr, 'i'},
            {"port-source", required_argument, nullptr, 's'},
            {"port-destination", required_argument, nullptr, 'd'},
            {"tcp", no_argument, nullptr, 't'},
            {"udp", no_argument, nullptr, 'u'},
            {"icmp4", no_argument, nullptr, 0},
            {"icmp6", no_argument, nullptr, 0},
            {"arp", no_argument, nullptr, 0},
            {"ndp", no_argument, nullptr, 0},
            {"igmp", no_argument, nullptr, 0},
            {"mld", no_argument, nullptr, 0},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0}
    };

    // Short options
    const char* shortOptions = "i::p:tuhn:";

    // Variables for storing parsed arguments and validation
    std::string interface;
    int numberOfPackets = 1;
    bool tcp = false;
    bool udp = false;
    bool icmp4 = false;
    bool icmp6 = false;
    bool arp = false;
    bool ndp = false;
    bool igmp = false;
    bool mld = false;
    int portSource = -1;
    int portDestination = -1;
    bool pflag = false;
    bool psflag = false;
    bool pdflag = false;

    /**
     * Prints all available interfaces, utilizing pcap library
     */
    void printAllInterfaces();

    /**
     * Prints the help message
     */
    void printHelp();

public:

    Parser() = default;

    /**
     * Parses the input arguments
     * @param argc
     * @param argv
     */
    void parseArguments(int argc, char **argv);

    /**
     * Validates the parsed arguments
     * @return true if the arguments are valid, false otherwise
     */
    bool validateArguments();


    // Accessors for the parsed arguments, needed for FilterCreator and Sniffer classes
    std::string getInterface() const;
    int getNumberOfPackets() const;
    bool getTcp() const;
    bool getUdp() const;
    bool getIcmp4() const;
    bool getIcmp6() const;
    bool getArp() const;
    bool getNdp() const;
    bool getIgmp() const;
    bool getMld() const;
    int getPortSource() const;
    int getPortDestination() const;

};


#endif //IPK_2_PARSER_H
