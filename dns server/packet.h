#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#define packed __attribute__((packed))



struct packed ip{
    uint8_t version_IHL; // version: 4, ihl:4
    uint8_t Dscp_ecn;    // dscp:6, ecn:2
    uint16_t Total_length;  
    uint16_t identification;  // identification:16
    uint16_t flag_fragment;  // flag:3 , fragment: 13
    uint8_t timetolive;    
    uint8_t protocol;
    uint16_t check_sum;
    uint32_t source;
    uint32_t destination;

};

struct packed ip_details{
    uint8_t version;
    uint8_t ihl;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_length;
    uint16_t identification;
    uint8_t flag;
    uint16_t fragment;
    uint8_t timetolive;
    uint8_t protocol;
    uint16_t check_sum;
    uint32_t source;
    uint32_t destination;
};



struct packed eth{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;

};

struct packed dns_header{
    uint16_t id;
    uint16_t flags;
    struct {
        uint16_t questions;
        uint16_t answers;
        uint16_t authority_rss;
        uint16_t additional_rss;
    }packed num;
};

struct packed dns_question_tail{
    uint16_t qtype;
    uint16_t qclass;
};

struct packed udp{
    uint16_t src;
    uint16_t dest;
    uint16_t len;
    uint16_t check_sum_udp;

};

struct packed packet_ptr{
    struct eth *eth;
    struct ip *ip;
    struct udp *udp;
    struct dns_header *dns_header;
    struct dns_question_tail *tail;
};



enum {
    ETH_SIZE = sizeof(struct eth),
    IP_SIZE  = sizeof(struct ip),
    UDP_SIZE = sizeof(struct udp),
    DNS_HEAD_SIZE = sizeof(struct dns_header),

    ETH_OFFSET = 0,
    IP_OFFSET  = ETH_OFFSET + ETH_SIZE,
    UDP_OFFSET = IP_OFFSET + IP_SIZE,
    DNS_OFFSET = UDP_OFFSET + UDP_SIZE,
    DATA_OFFSET = DNS_HEAD_SIZE + DNS_OFFSET,

    QUESTION_IPV4 = 0x01,
    QUESTION_INTERNET = 0X01,

    ETH_IPV4 = 0x0800
};


struct packet_ptr *packet_init(uint8_t[]);
int big_or_little();
void extract(struct ip*);
uint16_t conv16(uint16_t);
uint32_t conv32(uint32_t);
int get_endianness();
