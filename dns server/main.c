
#include "packet.h"

uint8_t raw_buffer[1500];

void init_checksum(struct packet_ptr *ptr);
void init_val_dns_tail(struct packet_ptr *ptr);
uint8_t *init_question(uint8_t *ptr);
uint16_t QUESTION_LENGTH = 0;

struct ip_details dflt_ip = {
    .version = 4,
    .ihl = 5,
    .dscp = 0,
    .ecn = 0,
    .total_length = 0x0028, // ip header + udp header + dns header (20 + 8 +12) + question(not included it's dynamic)
    .identification = 0x0000,
    .flag = 0x00,
    .fragment = 0,
    .timetolive = 64,
    .protocol = 17, // UDP
    .check_sum = 0x0000,
    .source = 0xC0A80125,
    .destination = 0x08080808
};

struct udp dflt_udp = {
    .src = 1030,
    .dest = 53,
    .len = 8 + 12, // udp header + dns header
    .check_sum_udp = 0x0000
};

struct dns_header dflt_dns ={
    .id = 0,
    .flags = 0,
    .num = {
        .questions = 1,
        .answers = 0,
        .authority_rss = 0,
        .additional_rss = 0,
    }
};


struct dns_flags dflt_flag = {
    .QR = 0,
    .OPCODE = 0,
    .AA = 0,
    .TC = 0,
    .RD = 1,
    .RA = 0,
    .Z = 0,
    .AD = 0,
    .CD = 0,
    .RCODE = 0

};

struct packet_ptr *packet_init(uint8_t buffer[]){
    struct packet_ptr *p = malloc(sizeof(struct packet_ptr));
    p->eth = (struct eth *)(buffer + ETH_OFFSET);
    p->ip = (struct ip *)(buffer + IP_OFFSET);
    p->udp = (struct udp *)(buffer + UDP_OFFSET);
    p->dns_header = (struct dns_header*) (buffer + DNS_OFFSET);

    uint8_t *ptr = buffer + DATA_OFFSET; 
    uint8_t *ques_start = ptr;

    // change this to a func
    ptr = init_question(ptr);
    // end func

    QUESTION_LENGTH = ptr - ques_start;
    p->tail = (struct dns_question_tail *)ptr;
    init_val_eth(p);
    init_val_ip(p);
    init_val_udp(p);
    init_val_dns_header(p);
    init_val_dns_tail(p); 
    init_checksum(p);
    return p;
}



void init_val_eth(struct packet_ptr *ptr){
    // need to complete
    struct eth *eth = ptr->eth;
    eth->src_mac;
    eth->dest_mac;
    eth->eth_type = conv16(ETH_IPV4);
}

void init_val_ip(struct packet_ptr *ptr){
    // need to complete
    struct ip *ip = ptr->ip;
    ip->version_IHL = (dflt_ip.version << 4) | dflt_ip.ihl;
    ip->Dscp_ecn = (dflt_ip.dscp << 2) | dflt_ip.ecn;
    ip->identification = conv16(dflt_ip.identification);
    ip->Total_length = conv16(dflt_ip.total_length + QUESTION_LENGTH);
    ip->flag_fragment = conv16((dflt_ip.flag << 13) | dflt_ip.fragment);
    ip->timetolive = dflt_ip.timetolive;
    ip->protocol = dflt_ip.protocol;
    ip->check_sum = conv16(dflt_ip.check_sum);
    ip->source = conv32(0xC0A80125);
    ip->destination = conv32(0x08080808);


}


    


void init_val_udp(struct packet_ptr *ptr){
    struct udp *udp = ptr->udp;
    udp->src = conv16(dflt_udp.src);
    udp->dest = conv16(dflt_udp.dest);
    udp->len = conv16(dflt_udp.len + QUESTION_LENGTH);
    udp->check_sum_udp = conv16(dflt_udp.check_sum_udp);

}

void init_val_dns_header(struct packet_ptr *ptr){
    struct dns_header *dns = ptr->dns_header;
    dns->id = conv16(dflt_dns.id);
    // initalizing all the flag
    uint16_t flag = 0;
    flag |= (dflt_flag.QR << 15);
    flag |= (dflt_flag.OPCODE << 11);
    flag |= (dflt_flag.AA << 10);
    flag |= (dflt_flag.TC << 9);
    flag |= (dflt_flag.RD << 8);
    flag |= (dflt_flag.RA << 7);
    flag |= (dflt_flag.Z << 6);
    flag |= (dflt_flag.AD << 5);
    flag |= (dflt_flag.CD << 4);
    flag |= (dflt_flag.RCODE);

    dns->flags = conv16(flag);
    dns->num.questions = conv16(dflt_dns.num.questions);
    dns->num.answers = conv16(dflt_dns.num.answers);
    dns->num.authority_rss = conv16(dflt_dns.num.authority_rss);
    dns->num.additional_rss = conv16(dflt_dns.num.additional_rss);


}


void init_val_dns_tail(struct packet_ptr *ptr){
    struct dns_question_tail *tail = ptr->tail;
    tail->qclass = conv16(QUESTION_INTERNET); 
    tail->qtype = conv16(QUESTION_IPV4);
}

uint16_t udp_checksum(struct packet_ptr *ptr){
    struct udp *udp = ptr->udp;
    struct ip *ip = ptr->ip;
    struct dns_header *dns = ptr->dns_header;
    uint32_t sum = 0;
    // ip header sum with essential fields
    sum += (ip->source >> 16) & 0xFFFF;
    sum += ip->source & 0xFFFF;

    sum += (ip->destination >> 16) & 0xFFFF;
    sum += ip->destination & 0xFFFF;

    sum += (uint16_t)(ip->protocol);
    sum += (udp->len + QUESTION_LENGTH);    

    // udp header sum
    sum += udp->src;
    sum += udp->dest;
    sum += udp->len;
    sum += udp->check_sum_udp;

    // dns header 
    sum += dns->flags;
    sum += dns->id;
    sum += dns->num.questions;
    sum += dns->num.answers;
    sum += dns->num.authority_rss;
    sum += dns->num.additional_rss;

    // question

    

    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

uint16_t ip_checksum(struct packet_ptr *ptr){
    struct ip *ip = ptr->ip;
    uint32_t sum = 0;

    sum += ((uint16_t)ip->version_IHL) << 8 | (ip->Dscp_ecn);
    sum += ip->identification;
    sum += ip->Total_length;
    sum += ip->flag_fragment;
    sum += ((uint16_t)ip->timetolive << 8) | ip->protocol;
    sum += ip->check_sum;

    // ip address
    sum += (ip->source >> 16) & 0xFFFF;
    sum += ip->source & 0xFFFF;
    sum += (ip->destination >> 16) & 0xFFFF;
    sum += ip->destination & 0xFFFF;

    
    // folding convert to 16 bit
    while (sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

void init_checksum(struct packet_ptr *ptr){
    ptr->ip->check_sum = conv16(ip_checksum(ptr));
    ptr->udp->check_sum_udp = conv16(udp_checksum(ptr));
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

uint8_t *init_question(uint8_t *ptr){
    uint8_t *label_len_ptr = ptr++;
    uint8_t len = 0;
    char domain[] = "www.google.com";

    for (int i = 0; domain[i] != '\0'; i++){
        if(domain[i] == '.'){
            *label_len_ptr = len;
            label_len_ptr = ptr++;
            len = 0;
        }else{
            *ptr++ = domain[i];
            len++;
        }
    }
    *label_len_ptr = len;
    *ptr++ = '\0';

    return ptr;
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
    

    printf("\n\n\n");
    packet_init(raw_buffer);

    for(int i = 0; i<200;i++){
        printf("%02x,", raw_buffer[i]);
    }

    return 0;

  
}
