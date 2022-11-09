/**
 * @file types.h
 * @author peng lei (plhitsz@outlook.com)
 * @brief
 * @version 0.1
 * @date 2022-10-26
 *
 * @copyright Copyright (c) 2022
 *
 */
#ifndef SRC_TYPES_H_
#define SRC_TYPES_H_
#include <arpa/inet.h>

#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <vector>

inline uint32_t IpStringToInt(const std::string& ip) {
  struct in_addr tmp_addr;
  inet_aton(ip.c_str(), &tmp_addr);
  return (uint32_t)tmp_addr.s_addr;
}

inline std::string IntToIpString(uint32_t value) {
  struct in_addr tmp_addr;
  tmp_addr.s_addr = value;
  return std::string(inet_ntoa(tmp_addr));
}

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
    os << IntToIpString(rh.dst) << "\t";
    os << IntToIpString(rh.gw) << "\t";
    os << inet_ntoa(mask_addr) << "\t\t";
    os << rh.metric << "\t";
    os << rh.iface_name << "\t";
    return os;
  }
  int dst_len;
  int iface;
  int metric;
  uint32_t dst, gw;
  std::string iface_name;
};

struct cmp_route {
  bool operator()(const RouteItem& lh, const RouteItem& rh) const {
    std::string lh_str = IntToIpString(lh.dst) + IntToIpString(lh.gw) +
                         std::to_string(lh.metric);
    std::string rh_str = IntToIpString(rh.dst) + IntToIpString(rh.gw) +
                         std::to_string(rh.metric);
    return lh_str > rh_str;
  }
};

// FIXME: optizmie the data structure
using RouteTable = std::set<RouteItem, cmp_route>;

inline std::ostream& operator<<(std::ostream& os, const RouteTable& input) {
  os << "\nDestination     Gateway         Genmask         Metric Iface\n";
  for (auto& item : input) {
    os << item << "\n";
  }
  return os;
}

#endif  // SRC_TYPES_H_
