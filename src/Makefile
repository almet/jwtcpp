BINARIES = jwtcpp tests
SOURCES = jwt.cpp utils.cpp
TARGETS = $(BINARIES)

LINK.o = g++

CFLAGS += -Werror -pedantic -Wall

CXXFLAGS += $(CFLAGS)

.PHONY : clean

all: $(TARGETS)

jwtcpp: clean
	g++ -o jwtcpp jwt.cpp utils.cpp -ljansson -lcryptopp -lpthread $(CXXFLAGS)

tests: clean
	g++ -o tests jwt.cpp utils.cpp tests.cpp -ljansson -lcryptopp -lpthread -lunittest++ $(CXXFLAGS)

clean: 
	rm -f *.exe* *.o $(TARGETS) *.bak *~
