/**
 * IPK 2nd project 2023/2024
 * Implementation of packet sniffer
 * @brief Header file for FilterCreator class
 * @Author Marek Effenberger
 * @file FilterCreator.h
 */

#ifndef IPK_2_FILTERCREATOR_H
#define IPK_2_FILTERCREATOR_H

#include "Parser.h"

/**
 * Class that creates a filter based on the given parser arguments
 */
class FilterCreator {

public:
    /**
     * Creates a filter based on the given parser arguments
     * @param parser
     * @return
     */
    static std::string createFilter(const Parser& parser);

};


#endif //IPK_2_FILTERCREATOR_H
