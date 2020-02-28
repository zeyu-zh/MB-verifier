CC := g++
CXXFLAGS := -std=c++11 -O2 -Wall  

SOURCES1 := $(wildcard *.cpp)
SOURCES2 := base64/base64.cpp
SOURCES3 := bloom/bloom.cpp
SOURCES4 := murmurhash/MurmurHash.cpp
SOURCES5 := $(wildcard verimb/*.cpp)
SOURCES6 := verimb/ac/ac_adaptor.cpp
SOURCES := $(SOURCES1) $(SOURCES2) $(SOURCES3) $(SOURCES4) $(SOURCES5) $(SOURCES6)

OBJECTS1 := $(patsubst %.cpp, %.o, $(SOURCES1))
OBJECTS2 := base64.o
OBJECTS3 := bloom.o
OBJECTS4 := MurmurHash.o
OBJECTS5 := pattern_loader.o pm_adaptor.o
OBJECTS6 := ac_adaptor.o


OBJECTS := $(OBJECTS1) $(OBJECTS2) $(OBJECTS3) $(OBJECTS4) $(OBJECTS5) $(OBJECTS6)
HEADERS :=  -Iipp/include -Iverimb -Iverimb/ac/ -Ibase64 -Ibloom -Imurmurhash -I/usr/local/include/ 

.PHONY = all
all:
	$(CC) -c $(CXXFLAGS) $(HEADERS) $(SOURCES)
	$(CC) -o ac-trie $(OBJECTS) -Lipp/lib/ -lippcp -static 

.PHONE = clean
clean:
	rm ./ac-trie *.o