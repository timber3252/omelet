//
// Created by timber3252 on 7/30/19.
//

#ifndef OMELET_SRC_LINUX_BASE_PACKET_HPP
#define OMELET_SRC_LINUX_BASE_PACKET_HPP

#include "address.hpp"
#include "include.hpp"

namespace ra {

#define OMELET_AL_BUFFER_SIZE 65536
#define OMELET_NL_BUFFER_SIZE 2048
#define OMELET_CMD_BUFFER_SIZE 256

struct OmeletHeader {
  uint8_t packet_source;
  uint8_t packet_type;
  uint16_t length;
  uint8_t virtual_ip_n[16]; // 使用网络字节序， 虚拟 IP 地址统一采用 IPv6

  OmeletHeader();

  void set(uint8_t source, uint8_t type, uint16_t len);
  void set(uint8_t source, uint8_t type, uint16_t len, ipv6_address_t addr);
};

struct OmeletSimpleHeader {
  uint8_t packet_source;
  uint8_t packet_type;
  uint16_t length;

  OmeletSimpleHeader();

  void set(uint8_t source, uint8_t type, uint16_t len);
};

template <size_t size> struct Packet {
  OmeletHeader header;
  uint8_t buf[size];

  uint8_t *data();
  const uint8_t *const_data() const;
};

template <size_t size> uint8_t *Packet<size>::data() {
  return reinterpret_cast<uint8_t *>(this);
}

template <size_t size> const uint8_t *Packet<size>::const_data() const {
  return reinterpret_cast<const uint8_t *>(this);
}

template <size_t size> struct SimplePacket {
  OmeletSimpleHeader header;
  uint8_t buf[size];

  uint8_t *data();
  const uint8_t *const_data() const;
};

template <size_t size> uint8_t *SimplePacket<size>::data() {
  return reinterpret_cast<uint8_t *>(this);
}

template <size_t size> const uint8_t *SimplePacket<size>::const_data() const {
  return reinterpret_cast<const uint8_t *>(this);
}

} // namespace ra

#endif // OMELET_SRC_LINUX_BASE_PACKET_HPP
