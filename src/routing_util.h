/**
 * @file routing_util.h
 * @author peng lei (plhitsz@outlook.com)
 * @brief some help functions to parse the routing from kernel.
 * @version 0.1
 * @date 2022-11-09
 *
 * @copyright Copyright (c) 2022
 *
 */
#ifndef SRC_ROUTING_UTIL_H_
#define SRC_ROUTING_UTIL_H_

#include "types.h"

/**
 * @brief Function to parse the route entry returned by netlink
 * Updates the route entry related map entries
 *
 */
void read_route(struct nlmsghdr *nh, int nll, RouteTable &table);
/**
 * @brief Recv a netlink msg from socket.
 *
 */
int recv_msg(struct sockaddr_nl sock_addr, int sock, char *buf_ptr,
             int buf_len);
/**
 * @brief Function to read the existing route table when the process is launched
 */
void get_route_table(int rtm_family, RouteTable &table);

#endif  // SRC_ROUTING_UTIL_H_
