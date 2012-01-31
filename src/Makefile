BINARIES = jwtcpp tests
SOURCES = jwt.cpp utils.cpp
TARGETS = $(BINARIES)

LINK.o = g++

CFLAGS += -Werror -pedantic

CXXFLAGS += $(CFLAGS)

.PHONY : clean

all: $(TARGETS)

tests: clean
	g++ -o tests tests.cpp utils.cpp -ljansson -lcryptopp -lpthread -lunittest++ $(CXXFLAGS)
	./tests

clean: 
	rm -f *.exe* *.o $(TARGETS) *.bak *~
