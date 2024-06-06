CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra

# Linker flags to link the necessary libraries
LDFLAGS = -L/usr/lib/x86_64-linux-gnu -lpcap

PROGRAM = ipk-sniffer
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(PROGRAM) $(OBJECTS)
