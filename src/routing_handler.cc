/**
 * @file routing_handler.cc
 * @author peng lei (plhitsz@outlook.com)
 * @brief
 * @version 0.1
 * @date 2022-10-25
 *
 * @copyright Copyright (c) 2022
 *
 */
#include "routing_handler.h"

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

#include <cassert>
#include <thread>

#include "routing_util.h"

namespace route {
/**
 * @brief start the daemon.
 *
 */
void RoutingHandler::start() {
  get_route_table(AF_INET, table_);
  std::cout << "Routing table init.";
  std::cout << table_;
  monitor_route();
  // std::thread keep_track(&RoutingHandler::monitor_route, this);
}
/**
 * @brief stop the daemon
 *
 */
void RoutingHandler::stop() { is_stop_ = true; }
/**
 * @brief monitor the routing notify from kernel.
 *
 */
void RoutingHandler::monitor_route() {
  char buf[8192];
  route_socket_ = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (route_socket_ < 0) {
    std::cout << "open netlink socket: %s" << strerror(errno);
    return;
  }

  fcntl(route_socket_, F_SETFL, O_NONBLOCK);

  struct sockaddr_nl lr;
  memset(&lr, 0, sizeof(lr));
  lr.nl_family = AF_NETLINK;
  // rigister the routing notify of ipv4, ipv6
  lr.nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY;
  if (bind(route_socket_, (struct sockaddr *)&lr, sizeof(lr)) < 0) {
    std::cout << "bind to netlink: " << strerror(errno);
    close(route_socket_);
    return;
  }

  struct pollfd fds_route;
  fds_route.fd = route_socket_;
  fds_route.events = POLL_IN;

  do {
    memset(buf, 0, sizeof(buf));
    if (poll(&fds_route, 1, -1) == POLL_IN) {
      int nll = recv_msg(lr, route_socket_, buf, 8192);
      if (nll < 0) {
        close(route_socket_);
        std::cout << "Recv msg error";
        return;
      }

      struct nlmsghdr *nh = (struct nlmsghdr *)buf;
      read_route(nh, nll, table_);
      std::cout << "Routing table updated.";
      std::cout << table_;
    }
  } while (!is_stop_);
  std::cout << "daemon thread exit";
}

}  // namespace route
