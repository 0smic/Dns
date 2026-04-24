#include "packet.h"

uint32_t conv32(uint32_t in);
uint16_t conv16(uint16_t in);
int big_or_little();
int get_endianness();

uint8_t raw_buffer[1500];

struct ip_details dflt_ip = {
    .version = 4,
    .ihl = 5,
    .dscp = 0,
    .ecn = 0

    
};


struct packet_ptr *packet_init(uint8_t buffer[]){
    struct packet_ptr *p = malloc(sizeof(struct packet_ptr));
    p->eth = (struct eth *)(buffer + ETH_OFFSET);
    p->ip = (struct ip *)(buffer + IP_OFFSET);
    p->udp = (struct udp *)(buffer + UDP_OFFSET);
    p->dns_header = (struct dns_header*) (buffer + DNS_OFFSET);

    uint8_t *ptr = buffer + DATA_OFFSET; 

    // change this to a func
    *ptr++ = 6;
    memcpy(ptr,"google",6);
    ptr += 6;

    *ptr++ = 3;
    memcpy(ptr,"com",3);
    ptr += 3;
    *ptr++ = 0;
    // end func

    p->tail = (struct dns_question_tail *)ptr;
    p->tail->qtype = conv16(QUESTION_IPV4);
    p->tail->qclass = conv16(QUESTION_INTERNET); 
    // fill the tail later
    return p;
}

void init_val_eth(struct packet_ptr *ptr){
    // need to complete
    struct eth *eth = ptr->eth;
    eth->src_mac;
    eth->dest_mac;
    eth->eth_type = conv32(ETH_IPV4);
}

void init_val_ip(struct packet_ptr *ptr){
    // need to complete
    struct ip *ip = ptr->ip;
    ip->version_IHL = (dflt_ip.version << 4) | dflt_ip.ihl;
    ip->Dscp_ecn = (dflt_ip.dscp << 2) | dflt_ip.ecn;
}


int big_or_little(){
    uint16_t i = 1;
    return *((uint8_t*)&i);
}

void extract(struct ip *packet){
    struct ip dup_packet = *packet;
    int little = get_endianness();
    uint8_t mask8;
    uint8_t version = dup_packet.version_IHL >> 4;
    uint8_t ihl = dup_packet.version_IHL & 0x0F;
    uint8_t dscp = dup_packet.Dscp_ecn >> 2;
    mask8 = (1 << 2) - 1;
    uint8_t ecn = dup_packet.Dscp_ecn & mask8;
    if(little){
        dup_packet.Total_length = conv16(dup_packet.Total_length);
        dup_packet.identification = conv16(dup_packet.identification);
        dup_packet.flag_fragment = conv16(dup_packet.flag_fragment);
        dup_packet.check_sum = conv16(dup_packet.check_sum);
        dup_packet.source = conv32(dup_packet.source);
        dup_packet.destination = conv32(dup_packet.destination);
    }
    uint16_t total_length = dup_packet.Total_length;
    uint16_t identification = dup_packet.identification;
    uint8_t flag = (dup_packet.flag_fragment >> 13) & 0x07;
    uint16_t mask16 = (1 << 13) - 1;
    uint16_t fragment = dup_packet.flag_fragment & mask16;
    uint8_t timetolive = dup_packet.timetolive;
    uint8_t protocol = dup_packet.protocol;
    uint16_t check_sum = dup_packet.check_sum;
    uint32_t source = dup_packet.source;
    uint32_t destination = dup_packet.destination;
}

uint16_t conv16(uint16_t in){
    return (uint16_t) ((in >> 8) | (in << 8));
}

uint32_t conv32(uint32_t in){
    return (((in >> 24) & 0x000000FF)  | 
            ((in << 24) & 0xFF000000)) | 
            (((in >> 8) & 0x0000FF00)  | 
            ((in << 8) & 0x00FF0000));
}

int get_endianness(){
    static int little = -1;
    if(little == -1)
        little = big_or_little();
    return little;
}

void display(struct ip *packet){

    uint8_t version = packet->version_IHL >> 4;
    uint8_t ihl = packet->version_IHL & 0x0F;

    uint8_t dscp = packet->Dscp_ecn >> 2;
    uint8_t ecn = packet->Dscp_ecn & 0x03;

    uint16_t flag_fragment = packet->flag_fragment;
    uint8_t flag = (flag_fragment >> 13) & 0x07;
    uint16_t fragment = flag_fragment & 0x1FFF;

    printf("------ IP HEADER ------\n");

    printf("Version        : %u\n", version);
    printf("IHL            : %u (%u bytes)\n", ihl, ihl * 4);

    printf("DSCP           : %u\n", dscp);
    printf("ECN            : %u\n", ecn);

    printf("Total Length   : %u\n", packet->Total_length);
    printf("Identification : %u\n", packet->identification);

    printf("Flags          : %u\n", flag);
    printf("Fragment Offset: %u\n", fragment);

    printf("TTL            : %u\n", packet->timetolive);
    printf("Protocol       : %u\n", packet->protocol);

    printf("Checksum       : 0x%04X\n", packet->check_sum);

    // Print IP addresses
    printf("Source IP      : %u.%u.%u.%u\n",
        (packet->source >> 24) & 0xFF,
        (packet->source >> 16) & 0xFF,
        (packet->source >> 8)  & 0xFF,
        packet->source & 0xFF);

    printf("Destination IP : %u.%u.%u.%u\n",
        (packet->destination >> 24) & 0xFF,
        (packet->destination >> 16) & 0xFF,
        (packet->destination >> 8)  & 0xFF,
        packet->destination & 0xFF);

    printf("------------------------\n");
}


int main(){
    
    uint8_t buffer[20] = {
        0x45,0x00,0x00,0x3c,0x1c,0x46,0x40,0x00,
        0x40,0x06,0xb1,0xe6,0xc0,0xa8,0x01,0x02,
        0xc0,0xa8,0x01,0x01
    };

    struct ip *packet = (struct ip*)buffer;
    extract(packet);
    display(packet);
    

    return 0;
}
