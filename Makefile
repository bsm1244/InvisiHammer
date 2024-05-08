CC = g++
CFLAGS = -Wall -ggdb -O0
OBJS = templating.o DRAMAddr.o

all: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o templating
		
templating.o: templating.cc
	$(CC) $(CFLAGS) -c templating.cc

DRAMAddr.o: DRAMAddr.cc
	$(CC) $(CFLAGS) -c DRAMAddr.cc

clean:
	rm -f *.o templating