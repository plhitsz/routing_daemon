/**
 * @file routing_utils.cc
 * @author peng lei (peng.lei@n-hop.com)
 * @brief
 * @version 0.1
 * @date 2022-11-09
 *
 * @copyright Copyright (c) 2022
 *
 */
#include "routing_utils.h"

#include <asm/types.h>
#include <fcntl.h>
#include <glog/logging.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

uint32_t read_ip_address(const std::string& ifname);
#define NLMSG_TAIL(nmsg) \
  ((struct rtattr*)(((void*)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

typedef struct {
  char family;
  char bitlen;
  unsigned char data[sizeof(struct in6_addr)];
} _inet_addr;

static void print_ext_ack_msg(bool is_err, const char* msg) {
  fprintf(stderr, "%s: %s", is_err ? "Error" : "Warning", msg);
  if (msg[strlen(msg) - 1] != '.') fprintf(stderr, ".");
  fprintf(stderr, "\n");
}

static int err_attr_cb(const struct nlattr* attr, void* data) {
  const struct nlattr** tb = (const struct nlattr**)data;
  uint16_t type;

  if (mnl_attr_type_valid(attr, NLMSGERR_ATTR_MAX) < 0) {
    fprintf(stderr, "Invalid extack attribute\n");
    return MNL_CB_ERROR;
  }

  type = mnl_attr_get_type(attr);
  enum mnl_attr_data_type mnl_type = MNL_TYPE_U32;
  switch (type) {
    case NLMSGERR_ATTR_MSG:
      mnl_type = MNL_TYPE_NUL_STRING;
      break;
    case NLMSGERR_ATTR_OFFS:
      mnl_type = MNL_TYPE_U32;
      break;
    default:
      break;
  }
  if (mnl_attr_validate(attr, mnl_type) < 0) {
    fprintf(stderr, "extack attribute %d failed validation\n", type);
    return MNL_CB_ERROR;
  }

  tb[type] = attr;
  return MNL_CB_OK;
}

int read_addr(const char* addr, _inet_addr* res) {
  if (strchr(addr, ':')) {
    res->family = AF_INET6;
    res->bitlen = 128;
  } else {
    res->family = AF_INET;
    res->bitlen = 32;
  }
  return inet_pton(res->family, addr, res->data);
}

int addattr_l(struct nlmsghdr* n, int maxlen, int type, const void* data,
              int alen) {
  int len = RTA_LENGTH(alen);
  struct rtattr* rta;

  if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
    fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n", maxlen);
    return -1;
  }
  rta = NLMSG_TAIL(n);
  rta->rta_type = type;
  rta->rta_len = len;
  if (alen) memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
  return 0;
}

void handle_err_msg(struct nlmsghdr* nh) {
  struct nlattr* tb[NLMSGERR_ATTR_MAX + 1] = {};
  const struct nlmsgerr* err = (struct nlmsgerr*)mnl_nlmsg_get_payload(nh);
  const struct nlmsghdr* err_nlh = NULL;
  unsigned int hlen = sizeof(*err);
  const char* msg = NULL;
  uint32_t off = 0;
  /* no TLVs, nothing to do here */
  if (!(nh->nlmsg_flags & NLM_F_ACK_TLVS)) {
    return;
  }
  /* if NLM_F_CAPPED is set then the inner err msg was capped */
  if (!(nh->nlmsg_flags & NLM_F_CAPPED)) {
    hlen += mnl_nlmsg_get_payload_len(&err->msg);
  }
  if (mnl_attr_parse(nh, hlen, err_attr_cb, tb) != MNL_CB_OK) {
    return;
  }
  if (tb[NLMSGERR_ATTR_MSG]) {
    msg = mnl_attr_get_str(tb[NLMSGERR_ATTR_MSG]);
  }
  print_ext_ack_msg(true, msg);
  std::cout << std::strerror(errno) << std::endl;
}

/* Function to parse the route entry returned by netlink
 * Updates the route entry related map entries
 */
RouteTable read_route(struct nlmsghdr* nh, int nll) {
  RouteTable table;
  if (nh->nlmsg_type == NLMSG_ERROR) {
    perror("netlink reported error");
    return table;
  }
  if (nh->nlmsg_type != RTM_GETROUTE && nh->nlmsg_type != RTM_DELROUTE &&
      nh->nlmsg_type != RTM_NEWROUTE) {
    SYSLOG(INFO) << "NOT READING Route entry" << (int)nh->nlmsg_type;
    return table;
  }
  for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
    if (nh->nlmsg_type == NLMSG_ERROR) {
      handle_err_msg(nh);
      continue;
    }
    struct rtmsg* rt_msg = (struct rtmsg*)NLMSG_DATA(nh);
    int rtm_family = rt_msg->rtm_family;
    if (rtm_family == AF_INET && rt_msg->rtm_table != RT_TABLE_MAIN) {
      continue;
    }
    char dsts[24], gws[24], ifs[16], dsts_len[24], metrics[24];
    memset(dsts, 0, sizeof(dsts));
    memset(dsts_len, 0, sizeof(dsts_len));
    memset(gws, 0, sizeof(gws));
    memset(ifs, 0, sizeof(ifs));

    struct rtattr* rt_attr = (struct rtattr*)RTM_RTA(rt_msg);
    int rtl = RTM_PAYLOAD(nh);
    for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
      switch (rt_attr->rta_type) {
        case NDA_DST:
          sprintf(dsts, "%u", (*((uint32_t*)RTA_DATA(rt_attr))));
          break;
        case RTA_GATEWAY:
          sprintf(gws, "%u", *((uint32_t*)RTA_DATA(rt_attr)));
          break;
        case RTA_OIF:
          sprintf(ifs, "%u", *((int*)RTA_DATA(rt_attr)));
          break;
        case RTA_METRICS:
          sprintf(metrics, "%u", *((int*)RTA_DATA(rt_attr)));
        default:
          break;
      }
    }
    RouteItem item;
    if (rtm_family == AF_INET) {
      sprintf(dsts_len, "%d", rt_msg->rtm_dst_len);
      item.dst_len = atoi(dsts_len);
      item.iface = atoi(ifs);
      item.metric = atoi(metrics);
      item.dst = bats::proto::IntToIpString(atoi(dsts));
      item.gw = bats::proto::IntToIpString(atoi(gws));
      item.iface_name.resize(IFNAMSIZ);
      if_indextoname(item.iface, item.iface_name.data());
      item.src = bats::proto::IntToIpString(read_ip_address(item.iface_name));
      table.push_back(item);
    }
  }
  return table;
}
/**
 * @brief Receiving a msg from kernel.
 *
 * @param sock
 * @param buf_ptr
 * @param buf_len
 * @return int
 */
int recv_msg(int sock, char* buf_ptr, int buf_len) {
  int nll = 0;
  while (1) {
    int len = recv(sock, buf_ptr, buf_len - nll, 0);
    if (len < 0) {
      return len;
    }
    struct nlmsghdr* nh = (struct nlmsghdr*)buf_ptr;
    if (nh->nlmsg_type == NLMSG_DONE) {
      break;
    }
    buf_ptr += len;
    nll += len;
    if (nh->nlmsg_type == NLMSG_ERROR) {
      break;
    }
  }
  return nll;
}
/**
 * @brief get the assigned ip address of the given interface.
 *
 * @param ifname
 * @return std::string
 */
uint32_t read_ip_address(const std::string& ifname) {
  struct ifreq ifr;
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    return 0;
  }
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, ifname.c_str(), ifname.length());
  if (ioctl(sock, SIOCGIFADDR, &ifr) != 0) {
    close(sock);
    return 0;
  }
  close(sock);

  struct in_addr ip = {INADDR_ANY};
  struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
  ip = sin->sin_addr;
  return ip.s_addr;
}
/**
 * @brief create a netlink socket to receive or send routing info.
 *
 * @return int
 */
int open_netlink_route_socket() {
  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0) {
    printf("open netlink socket: %s\n", strerror(errno));
    close(sock);
    return -1;
  }
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  // sa.nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY
  if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
    printf("bind to netlink: %s\n", strerror(errno));
    close(sock);
    return -1;
  }
  return sock;
}

int close_netlink_route_socket(int sock) {
  if (sock >= 0) {
    close(sock);
  }
}

/**
 * @brief build and send a routing request msg;
 *
 * @param msg
 * @param seq The seq of the msg.
 * @param target a destination address or "all".
 */
int do_request(int sock, int seq, const std::string& target) {
  struct {
    struct nlmsghdr nl;
    struct rtmsg rt;
    char buf[8192];
  } req;
  req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.nl.nlmsg_type = RTM_GETROUTE;

  req.rt.rtm_protocol = RTPROT_BOOT;
  req.rt.rtm_type = RTN_UNICAST;
  req.rt.rtm_flags = RTM_F_LOOKUP_TABLE;
  req.rt.rtm_table = RT_TABLE_MAIN;

  req.nl.nlmsg_pid = getpid();
  req.nl.nlmsg_seq = seq;

  if (target != "all") {
    // setting dst address
    _inet_addr dst_addr = {0};
    read_addr(target.c_str(), &dst_addr);
    addattr_l(&req.nl, sizeof(req), RTA_DST, &dst_addr.data, 4);
    req.rt.rtm_dst_len = dst_addr.bitlen;
    req.rt.rtm_family = dst_addr.family;
  } else {
    // request to dump all routing items.
    req.nl.nlmsg_flags = NLM_F_DUMP;
    req.rt.rtm_family = AF_INET;
  }
  /* Select scope, for simplicity we supports here only IPv6 and IPv4 */
  if (req.rt.rtm_family == AF_INET6) {
    req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
  } else {
    req.rt.rtm_scope = RT_SCOPE_LINK;
  }

  struct iovec iov;
  struct msghdr msg;
  memset(&msg, 0, sizeof(struct msghdr));
  iov.iov_base = (void*)&req.nl;
  iov.iov_len = req.nl.nlmsg_len;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  int ret = sendmsg(sock, &msg, 0);
  if (ret < 0) {
    printf("send to netlink: %s\n", strerror(errno));
    return -1;
  }
  return ret;
}
/**
 * @brief get the response from socket `sock` when a do-request is done.
 *
 * @param sock
 * @return RouteTable
 */
RouteTable handle_response(int sock) {
  char buf[8192];
  memset(buf, 0, sizeof(buf));
  int nll = recv_msg(sock, buf, 8192);
  if (nll < 0) {
    printf("recv from netlink: %s\n", strerror(nll));
    return RouteTable();
  }
  struct nlmsghdr* nh = (struct nlmsghdr*)buf;
  return read_route(nh, nll);
}
/**
 * @brief Get the route item for `dstip`.
 *
 * @param dstip
 * @return RouteTable
 */
RouteTable get_route_table(const std::string& dstip) {
  static int seq = 0;
  int sock = open_netlink_route_socket();
  if (sock < 0) {
    return RouteTable();
  }
  int ret = do_request(sock, seq++, dstip);
  if (ret < 0) {
    printf("send to netlink: %s\n", strerror(errno));
    close(sock);
    return RouteTable();
  }
  auto res = handle_response(sock);
  close(sock);
  return res;
}
