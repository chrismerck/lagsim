
all: inject-test pcap-test

inject-test: inject-test.o inject.o
	g++ inject-test.o inject.o -o inject-test

pcap-test: pcap-test.o 
	g++ -lpcap pcap-test.o -o pcap-test

inject.o: inject.c
	g++ -c inject.c

inject-test.o: inject-test.c
	g++ -c inject-test.c

clean:
	rm -rf *.o inject-test pcap-test
