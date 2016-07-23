#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <math.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

struct in_addr src;  //the IP address of source node
struct in_addr dst;  //The IP address of ultimate destination node
int fragmentCount = 0; //count the number of the fragments created from original datagram
int hasFragment = 0;   //sign bit: hasFragment == 1: datagram divided into fragments, otherwise datagram has no fragment
int theLastFragment = 0; //offset of the last fragment of the original datagram

int protocolArray[10]; //The values in the protocol field of IP headers. the values is sorted according to ascending order.
int protoSize = 0;	//count the num of protocol values
int firstPacket = 1;	//the firstPacket is sent by trace route, so we can record its src IP address and dst address
int start = 0;

struct datagramInfo{
	char key[50];
	int number_of_fragments;	
	int last_fragment_offset;
	unsigned char is_intermediate;
};



struct datagramInfo* datagramInfoArray;
int datagramInfoArrayLength;
int datagramInfoArraySize;

struct sendInfo{
	struct timeval time[1000];
	int head;
	int tail;
}sendQueue;

struct intermediateNode {
	struct in_addr ip;
	struct timeval sendTime[20];
	struct timeval recvTime[20];
//	int index;
	int size;
};

struct intermediateArray{
	struct intermediateNode intermediate[100];
	int size;
}inters;


int dump_packet(const unsigned char* packet, struct timeval ts, unsigned int capture_len) {
	struct ip *ip;
	unsigned int IP_header_len;


	if(capture_len < sizeof(struct ether_header)) {
		printf("error in ether_header size");
		return -1;
	}
	struct ether_header* ether = (struct ether_header*) packet;
	if(ntohs(ether->ether_type) != ETHERTYPE_IP) return -1;


	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	ip = (struct ip*) packet;
	IP_header_len = ip->ip_hl * 4;

	// packet += IP_header_len;
	// capture_len -= IP_header_len;
printf("capture length is %d\n", capture_len);
	if(capture_len < IP_header_len) {
		printf("error in ip header");
		return -1;
	}
	return 1;
}

void update_Send_Time(struct timeval ts) {
	sendQueue.time[sendQueue.tail++] = ts;
}


void update_Intermediates_value(int index, struct in_addr src_ip, struct timeval ts){
		inters.intermediate[index].ip = src_ip;
		inters.intermediate[index].size = 1;
		inters.intermediate[index].sendTime[0] = sendQueue.time[sendQueue.head++];
		inters.intermediate[index].recvTime[0] = ts;
		inters.size ++;
}


void update_Recv_Time(struct in_addr src_ip, struct timeval ts) {
	int index = 0;
	while(index < inters.size && (inters.intermediate[index].ip.s_addr!=src_ip.s_addr))
		index++;
	if(index == inters.size) {
		update_Intermediates_value(index, src_ip, ts);

	}else {
		int num = inters.intermediate[index].size++;
		inters.intermediate[index].sendTime[num] = sendQueue.time[sendQueue.head++];
		inters.intermediate[index].recvTime[num] = ts;
	}
}

void Protocol_Type(int type) {  //if find new protocol type, add it to the protocolTypesArray
	int index = 0;
	while(index<protoSize && type>protocolArray[index]) {
		index++;
	}
	if(index<protoSize && type==protocolArray[index]) return ;
	int i = protoSize;
	while(i>index) {
		protocolArray[i] = protocolArray[i-1];
		i--;
	}
	protocolArray[i] = type;
	protoSize++;
}

void updateDatagramInfo(char* key, unsigned short fragment_offset){
	printf("Key: %s Offset: %u\n", key, (fragment_offset * 8));
	int i;
	for(i = 0; i < datagramInfoArrayLength; i++){
		if(strcmp(datagramInfoArray[i].key, key) == 0){
			datagramInfoArray[i].number_of_fragments++;
			if(fragment_offset > datagramInfoArray[i].last_fragment_offset){
				datagramInfoArray[i].last_fragment_offset = fragment_offset * 8;
			}
			printf("Fragment detected!!!!\n");
			return;
		}
	}
	if(datagramInfoArrayLength == datagramInfoArraySize){
		datagramInfoArray = realloc(datagramInfoArray, sizeof(struct datagramInfo) * datagramInfoArraySize * 2);
		datagramInfoArraySize *= 2;
	}
	strcpy(datagramInfoArray[datagramInfoArrayLength].key, key);
	datagramInfoArray[datagramInfoArrayLength].number_of_fragments = 0;
	datagramInfoArray[datagramInfoArrayLength].last_fragment_offset = 0;
	datagramInfoArray[datagramInfoArrayLength].is_intermediate = 0;
	datagramInfoArrayLength++;
}

void analyze_packet(const unsigned char *packet, struct timeval ts, unsigned int cap_length){
	struct ip *ip;
	struct icmphdr *icmp;
	struct udphdr *udp;


//printf("icmp header caplen %d\n", icmp->caplen);
//printf("udp header caplen %d\n", udp->caplen);

//header.caplen -= sizeof(struct ether_header);
//printf("header caplen %d\n", capture_len);
	packet += sizeof(struct ether_header);
	ip = (struct ip*) packet;
	int protocol_type = ip->ip_p;
	int icmpHeaderOffset = ip->ip_hl << 2;
	printf("Header size: %d\n", icmpHeaderOffset);
	icmp = (struct icmphdr*) (packet + icmpHeaderOffset);
	int icmp_code = icmp->code;
	printf("IP_P: %d\n", ip->ip_p);
	char isIntermediateNode = (ip->ip_p == 1 && icmp->code == 0 &&icmp->type == 11);
	int temp = ip->ip_id;
	int id = (temp>>8) | (temp<<8);
	char src_ip_str[15];
	strcpy(src_ip_str, inet_ntoa(ip->ip_src));
	char dst_ip_str[15];
	strcpy(dst_ip_str, inet_ntoa(ip->ip_dst));
	char key[50];
	sprintf(key, "%s:%s:%d", src_ip_str, dst_ip_str, id);
	//printf(">>>>>%s\n", key);
	temp = ip->ip_off & 0xFF1F;
	unsigned short offset = (temp>>8) | (temp<<8);
	updateDatagramInfo(key, offset);
	//printf(">>>>%u\n", ip->ip_off);
	if(ip->ip_p == 1 && icmp->code == 0 &&icmp->type == 11){
		printf("ICMP_CODE: %u\n", icmp->code);
		printf("ICMP_TYPE: %u\n", icmp->type);
		printf("======Time-to-live exceeded======\n");
		printf("Src: %s\n", inet_ntoa(ip->ip_src));	
		printf("Dst: %s\n", inet_ntoa(ip->ip_dst));
	}
	Protocol_Type(protocol_type);
//	if(protocol_type != IPPROTO_ICMP) return ;
	if((ip->ip_p==IPPROTO_UDP) && (ip->ip_ttl==1) && firstPacket) { //the first packet is sent by the trace route. so the ip addr of the source node is the packet's source ip.the ip of the destination is ip dst of the packet
		src = ip->ip_src;
		dst = ip->ip_dst;
		firstPacket = 0;
		start = 1;
		sendQueue.head = 0;
		sendQueue.tail = 0;
//		sends.size = 0;
//		sends.used = 1;
		inters.size = 0;
	}
	if(start) {
//printf("src address is ------%s\n",inet_ntoa(src));
//printf("src add ------%s\n",inet_ntoa(ip->ip_src));
//printf("dst add ------%s\n",inet_ntoa(ip->ip_dst));
		if((ip->ip_src.s_addr != src.s_addr) && (ip->ip_dst.s_addr == src.s_addr) && isIntermediateNode) {
printf("add print start--------------\n");
printf("src add ------%s\n",inet_ntoa(ip->ip_src));
printf("dst add ------%s\n",inet_ntoa(ip->ip_dst));
			update_Recv_Time(ip->ip_src, ts);
			int i;
			char src_str[15];
			char dst_str[15];
			strcpy(src_str, inet_ntoa(src));
			strcpy(dst_str, inet_ntoa(dst));
			char tempPartialKey_Positive[50];
			sprintf(tempPartialKey_Positive, "%s:%s", src_str, dst_str);
			for(i = 0; i < datagramInfoArrayLength; i++){
				printf("key: %s, partial: %s\n", datagramInfoArray[i].key, tempPartialKey_Positive);
				if((strncmp(datagramInfoArray[i].key, tempPartialKey_Positive, strlen(tempPartialKey_Positive)) == 0)){
					printf(">>>>Pair matched\n");
					datagramInfoArray[i].is_intermediate = 1;
					printf(">>>>>>>>>>>>>>%d\n", datagramInfoArray[i].number_of_fragments);
				}
			}
printf("add print end--------------\n");
		}else {
            update_Send_Time(ts);
		}
	}
	if( !(ip->ip_off&IP_DF) && (ip->ip_off&IP_MF)) {  //check if the packet is the fragment of the original datagram
		fragmentCount++;
		hasFragment = 1;
	}else {
		if(hasFragment == 1) {
			fragmentCount++;
		}
		hasFragment = 0;
	}

	if(hasFragment == 0) { //IP_MF - 1: the fragment is the last one
	
		if(ip->ip_dst.s_addr != src.s_addr ){
		
			theLastFragment = cap_length;
			printf("the last frag is %d\n", cap_length);
			printf("bbbbbb\n");
		} 
//printf("add print start--------------\n");
//printf("src add ------%s\n",inet_ntoa(ip->ip_src));
//printf("dst add ------%s\n",inet_ntoa(ip->ip_dst));
//printf("add print end--------------\n");
//                printf("the last frag is %d\n", cap_length);
//                printf("bbbbbb\n");

	}
}

int convert_Time(struct timeval time) {
	return time.tv_sec*1000+time.tv_usec/1000;
}

void avgRTT(struct intermediateNode node) {

	int i = 0;
	int sum = 0;
	while(i < node.size) {
		sum += convert_Time(node.recvTime[i]) - convert_Time(node.sendTime[i]);
		i++;
	}
	int avg = sum/node.size;
	int dev = 0;
	i = 0;
	while(i < node.size) {
		int distance = convert_Time(node.recvTime[i])-convert_Time(node.sendTime[i])-avg;
		dev += distance*distance;
		i++;
	}
	dev = sqrt(dev);
	printf("The avg RRT between %s", inet_ntoa(src));
	printf(" and %s is: %dms,  the s.d. is: %d ms\n", inet_ntoa(node.ip), avg, dev);
}

void print_result() {
	int i = 0;
	printf("The IP address of the source node:%s\n", inet_ntoa(src));
	printf("The IP address of ultimate destination node:%s\n", inet_ntoa(dst));
	printf("The IP address of the intermediate destination nodes:\n");
	for(i=0; i<inters.size; i++) {

		printf("\trouter %d: %s\n",i, inet_ntoa(inters.intermediate[i].ip));
	}

	printf("\nThe values in the protocol field of IP headers:\n");
	for(i=0; i<protoSize; i++) {
		//convert Protocol type
		switch(protocolArray[i]) {
			case 1:
				printf("\t%d: %s\n", protocolArray[i], "ICMP");
				break;
			case 6:
				printf("\t%d: %s\n", protocolArray[i], "TCP");
				break;
			case 17:
				printf("\t%d: %s\n", protocolArray[i], "UDP");
				break;
			default :
				printf("Other protocol:%d, please check in.h", protocolArray[i]);
		}
	}
	int j = 0;
	for(i = 0; i < datagramInfoArrayLength; i++){
		if(!datagramInfoArray[i].is_intermediate){
			continue;
		}
		printf("The number of fragments created from the original datagram D%d is:%d\n",j, datagramInfoArray[i].number_of_fragments);
		printf("The offset of the last fragment is: %d\n", datagramInfoArray[i].last_fragment_offset);
		j++;
	}
//	for(i=1; i<(fragmentCount/2)+1; i++) {
//		printf("The number of fragments created from the original datagram D%d is:%d\n",i, (fragmentCount/fragmentCount));
//		printf("The offset of the last fragment is: %d\n", theLastFragment);
//	}
	printf("\n");
	for(i=0; i<inters.size; i++) {
		avgRTT(inters.intermediate[i]);
		printf("inters size is:%d\n ", inters.intermediate[i]);
	}
}

int main(int argc, char *argv[]){
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	datagramInfoArray = malloc(sizeof(struct datagramInfo) * 1);
	datagramInfoArrayLength = 0;
	datagramInfoArraySize = 1;


	if (argc < 2){
		fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
		exit(1);
	}

	pcap = pcap_open_offline(argv[1], errbuf);
	if(pcap==NULL)
	{
		printf("pcap open error\n");
		return 1;
	}
	while((packet=pcap_next(pcap, &header)) != NULL){
		if(dump_packet(packet, header.ts, header.caplen) == 1){
			analyze_packet(packet, header.ts, header.caplen);
		}
	}
//	printf("%d\t%d", sendNum, recvNum);
	pcap_close(pcap);
	print_result();
	return 0;
}
