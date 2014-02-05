
all: inject-test pcap-test lagsim

inject-test: inject-test.o inject.o
	g++ inject-test.o inject.o -o inject-test

lagsim: lagsim.o 
	g++ -lpthread lagsim.o -o lagsim

pcap-test: pcap-test.o crc32.o
	g++ -lpcap crc32.o pcap-test.o -o pcap-test

lagsim.o: lagsim.cpp
	g++ -c lagsim.cpp

pcap-test.o: pcap-test.c
	g++ -c pcap-test.c

crc32.o: crc32.c
	g++ -c crc32.c

inject.o: inject.c
	g++ -c inject.c

inject-test.o: inject-test.c
	g++ -c inject-test.c

clean:
	rm -rf *.o inject-test pcap-test lagsim
