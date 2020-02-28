CC := g++
CXXFLAGS := -std=c++11 -O2 -Wall -I/usr/local/include/

SOURCES := $(wildcard *.cpp) $(wildcard ./Verimb/*.cpp) $(wildcard ./Verimb/ac/*.cpp)
OBJECTS := $(patsubst %.cpp, %.o, $(SOURCES))
HEADERS :=  -Iverimb -Iverimb/ac/

.PHONY = all
all:
	$(CC) $(CXXFLAGS) $(HEADERS) $(SOURCES) -o ac-trie

.PHONE = clean
clean:
	rm ./ac-trie