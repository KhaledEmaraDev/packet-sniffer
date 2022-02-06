#include "syn_attack.h"
#include <mutex>

#define SYN_THRESHOLD 10
#define SYN_PERIOD 5

struct syn_entry {
  uint32_t count;
  steady_clock::time_point timestamp;
  set<uint32_t> acks;
};

map<string, syn_entry> syn_map;
mutex syn_map_mutex;

bool vaild_request(string dst_ip) {
  uint32_t diff =
      duration_cast<seconds>(steady_clock::now() - syn_map[dst_ip].timestamp)
          .count();
  if (syn_map[dst_ip].count > SYN_THRESHOLD && diff < SYN_PERIOD) {
    cout << "SYN attack detected" << endl;
    return false;
  } else if (diff >= SYN_PERIOD) {
    syn_map[dst_ip].count = 1;
  }

  syn_map[dst_ip].timestamp = steady_clock::now();
  return true;
}

bool is_syn_attck(string src_ip, string dst_ip, bool is_sent, struct tcphdr *tcp_hdr) {
  if (tcp_hdr->syn && tcp_hdr->ack && is_sent) {
    syn_map[dst_ip].count++;
    syn_map[dst_ip].acks.insert(tcp_hdr->seq + 1);

    if (!vaild_request(dst_ip)) {
      return true;
    }
  } else if (tcp_hdr->ack && !is_sent) {
    if (syn_map[src_ip].acks.count(tcp_hdr->ack_seq)) {
      syn_map[src_ip].count--;
      syn_map[src_ip].acks.erase(tcp_hdr->ack_seq);
    }
  }
  return false;
}
