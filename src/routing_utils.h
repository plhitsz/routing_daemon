/**
 * @file routing_utils.h
 * @author peng lei (peng.lei@n-hop.com)
 * @brief
 * @version 0.1
 * @date 2022-11-09
 *
 * @copyright Copyright (c) 2022
 *
 */
#ifndef SRC_BATS_PROTOCOL_ROUTING_ROUTING_UTILS_H_
#define SRC_BATS_PROTOCOL_ROUTING_ROUTING_UTILS_H_

#include <memory>
#include <string>
#include <vector>

//#include "utilities/base.h"

class RouteItem {
 public:
  RouteItem() = default;
  ~RouteItem() = default;
  RouteItem(const RouteItem&) = default;
  RouteItem& operator=(const RouteItem&) = default;
  friend bool operator==(const RouteItem& lh, const RouteItem& rh) {
    return (lh.dst == rh.dst && lh.dst_len == rh.dst_len && lh.gw == rh.gw &&
            lh.metric == rh.metric);
  }
  friend std::ostream& operator<<(std::ostream& os, const RouteItem& rh) {
    struct in_addr mask_addr;
    mask_addr.s_addr = htonl(~(0xffffffffU >> rh.dst_len));
    os << (rh.src) << "\t";
    os << (rh.dst) << "\t\t";
    os << (rh.gw) << "\t\t";
    os << inet_ntoa(mask_addr) << "\t\t";
    os << rh.metric << "\t\t";
    os << rh.iface_name << "\t";
    return os;
  }
  int dst_len;
  int iface;
  int metric;
  std::string dst, src, gw;
  std::string iface_name;
};

struct cmp_route {
  bool operator()(const RouteItem& lh, const RouteItem& rh) const {
    std::string lh_str = (lh.dst) + (lh.gw) + std::to_string(lh.metric);
    std::string rh_str = (rh.dst) + (rh.gw) + std::to_string(rh.metric);
    return lh_str > rh_str;
  }
};

// FIXME: optizmie the data structure
using RouteTable = std::vector<RouteItem>;

inline std::ostream& operator<<(std::ostream& os, const RouteTable& input) {
  os << "\nSource\t\tDestination\t\tGateway\t\tGenmask\t\tMetric\t\tIface\n";
  for (auto& item : input) {
    os << item << "\n";
  }
  return os;
}
// routing table operation function.
int open_netlink_route_socket();
int close_netlink_route_socket(int sock);
int do_request(int sock, int seq, const std::string& target);
RouteTable handle_response(int sock);

// equal to `ip route get `dstip``
RouteTable get_route_table(const std::string& dstip);

#endif  // SRC_BATS_PROTOCOL_ROUTING_ROUTING_UTILS_H_
