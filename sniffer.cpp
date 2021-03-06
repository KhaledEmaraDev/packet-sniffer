#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <getopt.h>
#include <iostream>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "syn_attack.h"

using namespace std;
using namespace chrono;

constexpr int THRESHOLD = 2; // requests
constexpr int PERIOD = 5;    // seconds

steady_clock::time_point initial_time;

deque<pair<int, string>> dq;
map<string, int> passed;

bpf_u_int32 ip, subnet_mask;

bool is_within_rate_limit(string src_ip, int timestamp) {
  while (!dq.empty() && dq.front().first <= timestamp - PERIOD) {
    passed[dq.front().second]--;
    dq.pop_front();
  }

  if (passed[src_ip] >= THRESHOLD) {
    return false;
  }

  dq.emplace_back(timestamp, src_ip);
  passed[src_ip]++;

  return true;
}

std::string exec(const char *cmd) {
  std::array<char, 128> buffer;
  std::string result;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
  if (!pipe) {
    throw std::runtime_error("popen() failed!");
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }
  return result;
}

void block_ip(string src_ip) {
  string block_rule =
      "nft add rule ip filter input ip saddr " + src_ip + " counter drop";
  printf("%s\n", block_rule.c_str());
  printf("%s\n", exec(block_rule.c_str()).c_str());
}

void packet_handler(u_char *arg,
                    const struct pcap_pkthdr *packet_header
                    __attribute__((unused)),
                    const u_char *packet) {
  int link_hdr_len = *((int *)arg);

  struct ip *ip_hdr;
  struct icmp *icmp_hdr;
  struct tcphdr *tcp_hdr;
  struct udphdr *udp_hdr;
  char ip_hdr_info[256], src_ip[256], dst_ip[256];

  packet += link_hdr_len;
  ip_hdr = (struct ip *)packet;
  strcpy(src_ip, inet_ntoa(ip_hdr->ip_src));
  strcpy(dst_ip, inet_ntoa(ip_hdr->ip_dst));

  bool is_sent = (ip_hdr->ip_src.s_addr & subnet_mask) == ip;

  sprintf(ip_hdr_info, "ID:%d TOS:0x%x, TTL:%d IpHdrLen:%d DatagramLen:%d",
          ntohs(ip_hdr->ip_id), ip_hdr->ip_tos, ip_hdr->ip_ttl,
          4 * ip_hdr->ip_hl, ntohs(ip_hdr->ip_len));

  packet += 4 * ip_hdr->ip_hl;

  switch (ip_hdr->ip_p) {
  case IPPROTO_TCP:
    tcp_hdr = (struct tcphdr *)packet;
    printf("TCP  %s:%d -> %s:%d\n", src_ip, ntohs(tcp_hdr->th_sport), dst_ip,
           ntohs(tcp_hdr->th_dport));
    printf("%s\n", ip_hdr_info);
    printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
           (tcp_hdr->th_flags & TH_URG ? 'U' : '*'),
           (tcp_hdr->th_flags & TH_ACK ? 'A' : '*'),
           (tcp_hdr->th_flags & TH_PUSH ? 'P' : '*'),
           (tcp_hdr->th_flags & TH_RST ? 'R' : '*'),
           (tcp_hdr->th_flags & TH_SYN ? 'S' : '*'),
           (tcp_hdr->th_flags & TH_FIN ? 'F' : '*'), ntohl(tcp_hdr->th_seq),
           ntohl(tcp_hdr->th_ack), ntohs(tcp_hdr->th_win), 4 * tcp_hdr->th_off);

    if (is_syn_attck(src_ip, dst_ip, is_sent, tcp_hdr))
      block_ip(dst_ip);

    break;

  case IPPROTO_UDP:
    udp_hdr = (struct udphdr *)packet;
    printf("UDP  %s:%d -> %s:%d\n", src_ip, ntohs(udp_hdr->uh_sport), dst_ip,
           ntohs(udp_hdr->uh_dport));
    printf("%s\n", ip_hdr_info);
    break;

  case IPPROTO_ICMP:
    icmp_hdr = (struct icmp *)packet;
    printf("ICMP %s -> %s\n", src_ip, dst_ip);
    printf("%s\n", ip_hdr_info);
    printf("Type:%d Code:%d ID:%d Seq:%d\n", icmp_hdr->icmp_type,
           icmp_hdr->icmp_code, ntohs(icmp_hdr->icmp_hun.ih_idseq.icd_id),
           ntohs(icmp_hdr->icmp_hun.ih_idseq.icd_seq));

    auto temp_stop = steady_clock::now();
    int current_second = duration_cast<seconds>(temp_stop - initial_time)
                             .count(); // relative to initial time;

    if (!is_within_rate_limit(string(src_ip), current_second))
      block_ip(src_ip);

    break;
  }
  printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
}

int main(int argc, char **argv) {
  initial_time = steady_clock::now();

  printf("%s\n", exec("nft add table ip filter").c_str());
  printf("%s\n", exec("nft 'add chain ip filter input { type filter hook input "
                      "priority 0 ; "
                      "}'")
                     .c_str());

  const char *dev = "";
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_if_t *devs = NULL;
  pcap_t *fd;
  struct bpf_program filter;
  char filter_expression[256] = "";
  int link_type, link_hdr_len;

  int c;
  static struct option long_options[] = {
      {"interface", required_argument, NULL, 'i'}, {NULL, 0, NULL, 0}};
  while ((c = getopt_long(argc, argv, "i:", long_options, NULL)) != -1) {
    switch (c) {
    case 'i':
      dev = optarg;
      break;
    case '?':
      break;
    default:
      printf("?? getopt returned character code 0%o ??\n", c);
    }
  }

  while (optind < argc) {
    strcat(filter_expression, argv[optind++]);
    strcat(filter_expression, " ");
  }

  if (!*dev && pcap_findalldevs(&devs, error_buffer)) {
    printf("pcap_findalldevs(): %s\n", error_buffer);
    return 2;
  } else if (!*dev) {
    dev = devs[0].name;
  }

  if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
    printf("pcap_lookupnet(%s): %s\n", dev, error_buffer);
    ip = 0;
    subnet_mask = 0;
  }

  fd = pcap_open_live(dev, BUFSIZ, 0, 10000, error_buffer);
  if (fd == NULL) {
    printf("Could not pcap_open_live(%s): %s\n", dev, error_buffer);
    return 2;
  }
  if (pcap_compile(fd, &filter, filter_expression, 0, ip) == -1) {
    printf("pcap_compile(): %s\n", pcap_geterr(fd));
    return 2;
  }
  if (pcap_setfilter(fd, &filter) == -1) {
    printf("pcap_setfilter(): %s\n", pcap_geterr(fd));
    return 2;
  }
  if ((link_type = pcap_datalink(fd)) < 0) {
    printf("pcap_datalink(): %s\n", pcap_geterr(fd));
    return 2;
  }

  switch (link_type) {
  case DLT_NULL:
    link_hdr_len = 4;
    break;

  case DLT_EN10MB:
    link_hdr_len = 14;
    break;

  case DLT_SLIP:
  case DLT_PPP:
    link_hdr_len = 24;
    break;

  default:
    printf("unsupported data link protocol (%d)\n", link_type);
    return 2;
  }
  pcap_loop(fd, -1, packet_handler, (u_char *)&link_hdr_len);
  return 0;
}
