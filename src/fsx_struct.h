#ifndef __MAP_STRUCTURES
#define __MAP_STRUCTURES

#include <linux/types.h>

#define MAX_PCKT_LENGTH 65536
#define MAX_TRACK_IPS 100000

#define __u128 __uint128_t

struct stats    
{
    __u64 allowed;
    __u64 dropped;
};

struct ip_stats
{
    __u64 pps;          // packets per second
    __u64 bps;          // bytes per second
    __u64 track_time;   // time at which the packet arrived
};

struct tcp_rst_port_node{
    __u64 port_time;
    __u32 rst_cnt;
    struct bpf_spin_lock semaphore;
};

struct tcp_syn__u128 {
    __u64 hi; // Higher 64 bits for IPv6
    __u64 lo; // Lower 64 bits for IPv6
};

union tcp_syn_ip_address {
    __u32 ipv4;           // 32-bit IPv4 address
    struct tcp_syn__u128 ipv6;   // 128-bit IPv6 address
};

struct tcp_syn_packet_id_key{
    union tcp_syn_ip_address ipadd; // IPv4 or IPv6
    __u16 dest;
    __u16 source;
    __u8 ip_type;
};
struct Semp{
    struct bpf_spin_lock semaphore;
};

struct icmp_rate_limit_data {
    __u64 last_reset_time; 
    __u32 packet_count;     
}; 

struct udp_port_stat {
    __u32 packet_count;
    __u64 last_check;
};

#endif