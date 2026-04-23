#include "packet.h"

uint32_t conv32(uint32_t in);
uint16_t conv16(uint16_t in);
int big_or_little();
int get_endianness();




int big_or_little(){
    uint16_t i = 1;
    return *((uint8_t*)&i);
}

void extract(struct ip *packet){
    int little = get_endianness();
    uint8_t mask8;
    uint8_t version = packet->version_IHL >> 4;
    uint8_t ihl = packet->version_IHL & 0x0F;
    uint8_t dscp = packet->Dscp_ecn >> 2;
    mask8 = (1 << 2) - 1;
    uint8_t ecn = packet->Dscp_ecn & mask8;
    if(little){
        packet->Total_length = conv16(packet->Total_length);
        packet->identification = conv16(packet->identification);
        packet->flag_fragment = conv16(packet->flag_fragment);
        packet->check_sum = conv16(packet->check_sum);
        packet->source = conv32(packet->source);
        packet->destination = conv32(packet->destination);
    }
    uint16_t total_length = packet->Total_length;
    uint16_t identification = packet->identification;
    uint8_t flag = (packet->flag_fragment >> 13) & 0x07;
    uint16_t mask16 = (1 << 13) - 1;
    uint16_t fragment = packet->flag_fragment & mask16;
    uint8_t timetolive = packet->timetolive;
    uint8_t protocol = packet->protocol;
    uint16_t check_sum = packet->check_sum;
    uint32_t source = packet->source;
    uint32_t destination = packet->destination;
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

    struct ip_packet *packet = (struct ip_packet*)buffer;
    extract(packet);
    display(packet);
    

    return 0;
}
