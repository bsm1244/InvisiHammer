CC = g++
CFLAGS = -Wall -ggdb -O0
OBJS = templating.o DRAMAddr.o utils.o

all: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o templating
		
templating.o: templating.cc
	$(CC) $(CFLAGS) -c templating.cc

DRAMAddr.o: DRAMAddr.cc
	$(CC) $(CFLAGS) -c DRAMAddr.cc

utils.o: utils.cc
	$(CC) $(CFLAGS) -c utils.cc

clean:
	rm -f *.o templating