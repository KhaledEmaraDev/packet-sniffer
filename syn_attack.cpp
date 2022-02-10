#include "syn_attack.h"
#include <cstdint>
#include <mutex>

#define SYN_THRESHOLD 10
#define SYN_RST_THRESHOLD 10
#define SYN_PERIOD 5

struct syn_entry {
  steady_clock::time_point timestamp;
  set<uint32_t> acks;
  uint32_t rst_count;
};

map<string, syn_entry> syn_map;
mutex syn_map_mutex;

bool suspicious_request(string dst_ip) {
  uint32_t diff =
      duration_cast<seconds>(steady_clock::now() - syn_map[dst_ip].timestamp)
          .count();
  if ((syn_map[dst_ip].acks.size() > SYN_THRESHOLD ||
       syn_map[dst_ip].rst_count > SYN_RST_THRESHOLD) &&
      diff < SYN_PERIOD) {
    cout << "SYN attack detected" << endl;
    return true;
  } else if (diff >= SYN_PERIOD) {
    syn_map[dst_ip].acks.clear();
    syn_map[dst_ip].rst_count = 0;
  }

  syn_map[dst_ip].timestamp = steady_clock::now();
  return false;
}

bool is_syn_attck(string src_ip, string dst_ip, bool is_sent,
                  struct tcphdr *tcp_hdr) {
  if (tcp_hdr->syn && tcp_hdr->ack && is_sent) {
    if (suspicious_request(dst_ip)) {
      return true;
    }
    syn_map[dst_ip].acks.insert(tcp_hdr->seq + 1);
  } else if (tcp_hdr->rst && tcp_hdr->ack && is_sent) {
    if (suspicious_request(dst_ip)) {
      return true;
    }
    syn_map[dst_ip].rst_count++;
  } else if (tcp_hdr->ack && !is_sent) {
    syn_map[src_ip].acks.erase(tcp_hdr->ack_seq);
  }

  return false;
}

void clean_up_syn_map() {
  lock_guard<mutex> lock(syn_map_mutex);
  for (auto it = syn_map.begin(); it != syn_map.end();) {
    if (duration_cast<seconds>(steady_clock::now() - it->second.timestamp)
            .count() >= SYN_PERIOD) {
      it = syn_map.erase(it);
    } else {
      it++;
    }
  }
}
