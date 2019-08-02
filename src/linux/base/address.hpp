//
// Created by timber3252 on 7/30/19.
//

#ifndef OMELET_SRC_LINUX_BASE_ADDRESS_HPP
#define OMELET_SRC_LINUX_BASE_ADDRESS_HPP

#include "include.hpp"

namespace ra {

typedef uint16_t port_t;
typedef std::array<uint8_t, 16> ipv6_address_t;

class Address {
public:
  enum Family { IPv4, IPv6 };

  Address();
  Address(const std::string &ip);
  Address(const Address &other);
  Address(const ipv6_address_t &raw_ip);

  std::string to_string() const;

  bool is_v4() const;
  bool is_v6() const;

  static Address from_string(std::string ip);
  sockaddr_in6 &raw_sockaddr();

  // TODO: ipv4_address_t to_v4() const;

  ipv6_address_t raw_bytes() const;

  bool operator<(const Address &other) const;
  bool operator==(const Address &other) const;
  Address &operator++();

  void random();

private:
  Family _type;
  ipv6_address_t _addr6; // 网络字节序
  sockaddr_in6 _sa;
};

class Endpoint {
public:
  Endpoint();
  Endpoint(const std::string &ip, port_t port);
  Endpoint(const std::string &ip_and_port);
  Endpoint(const ipv6_address_t &ip, port_t port);
  Endpoint(const sockaddr_in6 &raw_addr6);

  const Address &address() const;
  const port_t &port() const;
  const sockaddr_in6 &raw_sockaddr();

private:
  Address _addr6;
  port_t _port;
};

} // namespace ra

#endif // OMELET_SRC_LINUX_BASE_ADDRESS_HPP
