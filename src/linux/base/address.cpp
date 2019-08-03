//
// Created by timber3252 on 7/30/19.
//

#include "address.hpp"

ra::Address::Address() : _type(IPv6) {
  _addr6.fill(0x00);
  _sa.sin6_family = AF_INET6;
  memset(_sa.sin6_addr.s6_addr, 0x00, sizeof _sa.sin6_addr);
}

ra::Address ra::Address::from_string(std::string ip) {
  Address addr;
  bool exist_dot = (ip.find('.') != std::string::npos);
  bool exist_colon = (ip.find(':') != std::string::npos);

  if (exist_dot && !exist_colon) {
    // IPv4 地址：转换为 IPv4 映射地址
    addr._type = IPv4;
    ip = "::ffff:" + ip;
  } else if (exist_dot && exist_colon) {
    // IPv4 映射地址
    addr._type = IPv4;
  } else if (!exist_dot && exist_colon) {
    // IPv6 地址
    addr._type = IPv6;
  }

  addr._sa.sin6_family = AF_INET6;
  inet_pton(addr._sa.sin6_family, ip.c_str(), (void *)(&addr._sa.sin6_addr));
  memcpy(addr._addr6.begin(), addr._sa.sin6_addr.s6_addr, 16);

  static const uint8_t ipv4_mapping_prefix[12] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};

  bool is_v4 = true;
  for (int i = 0; i < 12; ++i) {
    if (addr._addr6[i] != ipv4_mapping_prefix[i]) {
      is_v4 = false;
      break;
    }
  }

  if (is_v4) {
    addr._type = IPv4;
  }

  return addr;
}

ra::Address::Address(const std::string &ip) { *this = from_string(ip); }

ra::Address::Address(const ra::Address &other) {
  this->_type = other._type;
  this->_addr6 = other._addr6;
  this->_sa = other._sa;
}

bool ra::Address::is_v4() const { return _type == IPv4; }

bool ra::Address::is_v6() const { return _type == IPv6; }

std::string ra::Address::to_string() const {
  char str[INET6_ADDRSTRLEN];
  inet_ntop(_sa.sin6_family, &_sa.sin6_addr, str, INET6_ADDRSTRLEN);
  return std::string(str);
}

sockaddr_in6 &ra::Address::raw_sockaddr() { return _sa; }

bool ra::Address::operator<(const ra::Address &other) const {
  return _addr6 < other._addr6;
}

ra::Address &ra::Address::operator++() {
  for (int i = 15; i >= 0; --i) {
    if (_addr6[i] == 0xff) {
      _addr6[i] = 0x00;
    } else {
      ++_addr6[i];
      break;
    }
  }

  _type = IPv6;
  _sa.sin6_family = AF_INET6;
  std::copy(_addr6.begin(), _addr6.end(), _sa.sin6_addr.s6_addr);
  return *this;
}

void ra::Address::random() {
  std::default_random_engine e(time(nullptr));
  std::uniform_int_distribution<uint8_t> gen(0x00, 0xff);

  _addr6[0] = 0xfd;
  for (int i = 1; i <= 7; ++i) {
    _addr6[i] = gen(e);
  }
  for (int i = 8; i < 16; ++i) {
    _addr6[i] = 0x00;
  }

  _type = IPv6;
  _sa.sin6_family = AF_INET6;
  std::copy(_addr6.begin(), _addr6.end(), _sa.sin6_addr.s6_addr);
}

ra::Address::Address(const ra::ipv6_address_t &raw_ip) {
  sockaddr_in6 sa6{};
  sa6.sin6_family = AF_INET6;
  std::copy(raw_ip.begin(), raw_ip.end(), sa6.sin6_addr.s6_addr);

  char str[INET6_ADDRSTRLEN];
  inet_ntop(sa6.sin6_family,
            &(sa6.sin6_addr), str, INET6_ADDRSTRLEN);
  *this = from_string(str);
}

bool ra::Address::operator==(const ra::Address &other) const {
  return _addr6 == other._addr6;
}

ra::ipv6_address_t ra::Address::raw_bytes() const {
  ipv6_address_t ret;
  for (int i = 0; i < 16; ++i) {
    ret[i] = _sa.sin6_addr.s6_addr[i];
  }
  return ret;
}

std::optional<ra::ipv4_address_t> ra::Address::to_v4_addr() const {
  if (_type == IPv4) {
    ipv4_address_t addr;

    for (int i = 0; i < 4; ++i) {
      addr[i] = _addr6[i + 12];
    }

    return addr;
  } else {
    return {};
  }
}

std::optional<std::string> ra::Address::to_v4_string() const {
  if (_type == IPv4) {
    char str[INET_ADDRSTRLEN];
    uint8_t addr[4];

    for (int i = 0; i < 4; ++i) {
      addr[i] = _addr6[i + 12];
    }

    inet_ntop(AF_INET, addr, str, INET_ADDRSTRLEN);

    return std::string(str);
  } else {
    return {};
  }
}

ra::Endpoint::Endpoint(const std::string &ip, ra::port_t port)
    : _addr6(ip), _port(port) {
  _addr6.raw_sockaddr().sin6_port = htons(_port);
}

ra::Endpoint::Endpoint(const std::string &ip_and_port) : _addr6(), _port(0) {
  int pos = ip_and_port.find_last_of(':');

  _port = std::stoi(ip_and_port.substr(pos + 1));
  std::string ip = ip_and_port.substr(0, pos);
  if (ip.front() == '[' && ip.back() == ']') {
    ip = ip.substr(1, pos - 2);
  }

  _addr6 = Address::from_string(ip);
  _addr6.raw_sockaddr().sin6_port = htons(_port);
}

const ra::Address &ra::Endpoint::address() const { return _addr6; }

const ra::port_t &ra::Endpoint::port() const { return _port; }

const sockaddr_in6 &ra::Endpoint::raw_sockaddr() {
  return _addr6.raw_sockaddr();
}

ra::Endpoint::Endpoint() : _addr6(), _port(23367) {
  _addr6.raw_sockaddr().sin6_port = htons(_port);
}

ra::Endpoint::Endpoint(const sockaddr_in6 &raw_addr6) : _addr6(), _port(0) {
  _port = ntohs(raw_addr6.sin6_port);

  char str[INET6_ADDRSTRLEN];
  inet_ntop(raw_addr6.sin6_family,
            &(raw_addr6.sin6_addr), str, INET6_ADDRSTRLEN);
  _addr6 = Address::from_string(std::string(str));

//  printf("%s %d\n", str, _addr6.is_v4());

  _addr6.raw_sockaddr() = raw_addr6;
}

ra::Endpoint::Endpoint(const ra::ipv6_address_t &ip, ra::port_t port)
    : _addr6(ip), _port(port) {
  _addr6.raw_sockaddr().sin6_port = htons(_port);
}

bool ra::Endpoint::operator<(const ra::Endpoint &other) const {
  return _addr6 < other._addr6 || _port < other._port;
}

bool ra::Endpoint::operator==(const ra::Endpoint &other) const {
  return _addr6 == other._addr6 && _port == other._port;
}
