all : send_arp

send_arp : main.o
	g++ -g -o send_arp main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f pcap_test
	rm -f *.o
