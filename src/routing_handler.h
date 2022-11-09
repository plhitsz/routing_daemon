/**
 * @file routing_handler.h
 * @author peng lei (plhitsz@outlook.com)
 * @brief
 * @version 0.1
 * @date 2022-10-25
 *
 * @copyright Copyright (c) 2022
 *
 */
#ifndef SRC_ROUTING_HANDLER_H_
#define SRC_ROUTING_HANDLER_H_
#include <unistd.h>

#include <memory>

#include "types.h"

namespace route {

class RoutingHandler : public std::enable_shared_from_this<RoutingHandler> {
 public:
  RoutingHandler() = default;
  ~RoutingHandler() {
    if (route_socket_ != -1) {
      close(route_socket_);
    }
  }
  RoutingHandler(const RoutingHandler&) = delete;
  RoutingHandler& operator=(const RoutingHandler&) = delete;
  // run as a daemon thread.
  void start();
  // stop the daemon
  void stop();

 private:
  // keep track and update changes in route table from kernel.
  void monitor_route();

 private:
  RouteTable table_;
  int route_socket_ = -1;
  bool is_stop_ = false;
};

typedef std::shared_ptr<RoutingHandler> RoutingHandler_ptr;

}  // namespace route

#endif  // SRC_ROUTING_HANDLER_H_
