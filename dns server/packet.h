#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


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

struct packed dns_tail{
    uint16_t qtype;
    uint16_t qclass;
};

struct packed udp{
    uint16_t src;
    uint16_t dest;
    uint16_t len;
    uint16_t check_sum_udp;

};

struct packed packet{
    struct eth;
    struct ip;
    struct udp;
    struct dns;
};



enum {
    ETH_SIZE = sizeof(struct eth),
    IP_SIZE  = sizeof(struct ip),
    UDP_SIZE = sizeof(struct udp),

    ETH_OFFSET = 0,
    IP_OFFSET  = ETH_OFFSET + ETH_SIZE,
    UDP_OFFSET = IP_OFFSET + IP_SIZE,
    DNS_OFFSET = UDP_OFFSET + UDP_SIZE
};
