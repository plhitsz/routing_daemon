
/**
 * @file routing_util.cc
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2022-11-09
 *
 * @copyright Copyright (c) 2022
 *
 */
#include "routing_util.h"

#include <asm/types.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "types.h"

void read_route(struct nlmsghdr *nh, int nll, RouteTable &table) {
  if (nh->nlmsg_type != RTM_GETROUTE && nh->nlmsg_type != RTM_DELROUTE &&
      nh->nlmsg_type != RTM_NEWROUTE) {
    std::cout << "NOT READING Route entry" << (int)nh->nlmsg_type;
    return;
  }

  for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
    struct rtmsg *rt_msg = (struct rtmsg *)NLMSG_DATA(nh);
    int rtm_family = rt_msg->rtm_family;
    if (rtm_family == AF_INET && rt_msg->rtm_table != RT_TABLE_MAIN) {
      continue;
    }
    char dsts[24], gws[24], ifs[16], dsts_len[24], metrics[24];
    memset(dsts, 0, sizeof(dsts));
    memset(dsts_len, 0, sizeof(dsts_len));
    memset(gws, 0, sizeof(gws));
    memset(ifs, 0, sizeof(ifs));

    struct rtattr *rt_attr = (struct rtattr *)RTM_RTA(rt_msg);
    int rtl = RTM_PAYLOAD(nh);
    for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
      switch (rt_attr->rta_type) {
        case NDA_DST:
          sprintf(dsts, "%u", (*((uint32_t *)RTA_DATA(rt_attr))));
          break;
        case RTA_GATEWAY:
          sprintf(gws, "%u", *((uint32_t *)RTA_DATA(rt_attr)));
          break;
        case RTA_OIF:
          sprintf(ifs, "%u", *((int *)RTA_DATA(rt_attr)));
          break;
        case RTA_METRICS:
          sprintf(metrics, "%u", *((int *)RTA_DATA(rt_attr)));
        default:
          break;
      }
    }
    RouteItem item;
    if (rtm_family == AF_INET) {
      switch (nh->nlmsg_type) {
        case RTM_DELROUTE:
          /* Rereading the route table to check if
           * there is an entry with the same
           * prefix but a different metric as the
           * deleted enty.
           */
          // get_route_table(AF_INET, table);
          sprintf(dsts_len, "%d", rt_msg->rtm_dst_len);
          item.dst_len = atoi(dsts_len);
          item.iface = atoi(ifs);
          item.metric = atoi(metrics);
          item.dst = atoi(dsts);
          item.gw = atoi(gws);
          // FIXME: optizmie
          table.erase(table.find(item));
          break;
        case RTM_NEWROUTE:
          sprintf(dsts_len, "%d", rt_msg->rtm_dst_len);
          item.dst_len = atoi(dsts_len);
          item.iface = atoi(ifs);
          item.metric = atoi(metrics);
          item.dst = atoi(dsts);
          item.gw = atoi(gws);
          item.iface_name.resize(IFNAMSIZ);
          if_indextoname(item.iface, item.iface_name.data());
          table.insert(item);
          break;
        default:
          break;
      }
    }
  }
}

int recv_msg(struct sockaddr_nl sock_addr, int sock, char *buf_ptr,
             int buf_len) {
  int nll = 0;
  while (1) {
    int len = recv(sock, buf_ptr, buf_len - nll, 0);
    if (len < 0) {
      return len;
    }
    struct nlmsghdr *nh = (struct nlmsghdr *)buf_ptr;
    if (nh->nlmsg_type == NLMSG_DONE) {
      break;
    }

    buf_ptr += len;
    nll += len;
    if ((sock_addr.nl_groups & RTMGRP_NEIGH) == RTMGRP_NEIGH) {
      break;
    }
    if ((sock_addr.nl_groups & RTMGRP_IPV4_ROUTE) == RTMGRP_IPV4_ROUTE) {
      break;
    }
  }
  return nll;
}

void get_route_table(int rtm_family, RouteTable &table) {
  static int seq = 0;
  struct {
    struct nlmsghdr nl;
    struct rtmsg rt;
    char buf[8192];
  } req;

  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0) {
    printf("open netlink socket: %s\n", strerror(errno));
    close(sock);
    return;
  }
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    printf("bind to netlink: %s\n", strerror(errno));
    close(sock);
    return;
  }
  memset(&req, 0, sizeof(req));
  req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nl.nlmsg_type = RTM_GETROUTE;

  req.rt.rtm_family = rtm_family;
  req.rt.rtm_table = RT_TABLE_MAIN;
  req.nl.nlmsg_pid = 0;
  req.nl.nlmsg_seq = ++seq;

  struct msghdr msg;
  struct iovec iov;
  memset(&msg, 0, sizeof(msg));
  iov.iov_base = (void *)&req.nl;
  iov.iov_len = req.nl.nlmsg_len;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  int ret = sendmsg(sock, &msg, 0);
  if (ret < 0) {
    printf("send to netlink: %s\n", strerror(errno));
    close(sock);
    return;
  }
  char buf[8192];
  memset(buf, 0, sizeof(buf));
  int nll = recv_msg(sa, sock, buf, 8192);
  if (nll < 0) {
    printf("recv from netlink: %s\n", strerror(nll));
    close(sock);
    return;
  }
  struct nlmsghdr *nh = (struct nlmsghdr *)buf;
  read_route(nh, nll, table);
  close(sock);
}
