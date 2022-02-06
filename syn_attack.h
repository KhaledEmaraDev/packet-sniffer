#ifndef _SYN_ATTACK_H_
#define _SYN_ATTACK_H_

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <getopt.h>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <set>
#include <signal.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>

using namespace std;
using namespace chrono;

bool is_syn_attck(string src_ip, string dest, bool is_sent, struct tcphdr *tcp_hdr);

#endif
