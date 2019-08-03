//
// Created by timber3252 on 7/30/19.
//

#ifndef OMELET_SRC_LINUX_BASE_PACKET_HPP
#define OMELET_SRC_LINUX_BASE_PACKET_HPP

#include "address.hpp"
#include "include.hpp"

namespace ra {

// Buffer Size
#define OMELET_AL_BUFFER_SIZE 65536
#define OMELET_NL_BUFFER_SIZE 2048
#define OMELET_CMD_BUFFER_SIZE 256

// Protocol Type
#define PROTOCOL_OMELET 0xc1
#define PROTOCOL_RELAY 0xc2

// Packet Source
#define PACKET_FROM_CLIENT 0xd1
#define PACKET_FROM_SERVER 0xd2
#define PACKET_FROM_APP 0xd3
#define PACKET_FROM_API 0xd4
#define PACKET_FROM_PEERS 0xd5
#define PACKET_FROM_RELAY 0xd6

#define PACKET_RELAY_FROM_SERVER 0xd7
#define PACKET_RELAY_FROM_IPV6_CLIENT 0xd8
#define PACKET_RELAY_FROM_IPV4_CLIENT 0xd9

// Packet Type
//#define PACKET_HEARTBEAT 0x01
//#define PACKET_HANDSHAKE 0x02
#define PACKET_GET_ROUTERS 0x03
#define PACKET_VERIFICATION 0x04
#define PACKET_RAW_IP_PACKET 0x05
#define PACKET_LEAVE 0x06
//#define PACKET_HANDSHAKE_REQUEST 0x07
#define PACKET_LOCAL_GET_ROUTERS 0x08
#define PACKET_LOCAL_GET_VIRTUAL_IP 0x09
#define PACKET_SERVER_CLOSED 0x0a
#define PACKET_ERROR_SERVER_FULL 0x0b
#define PACKET_RELAY_RAW_TO_SERVER 0x0c
#define PACKET_RELAY_RAW_TO_PEERS 0x0d
#define PACKET_RELAY_VERIFICATION 0x0e
#define PACKET_RELAY_HEARTBEAT 0x0f

struct OmeletHeader {
  uint8_t protocol_id;
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

struct IPv4RelayHeader {
  uint8_t protocol_id;
  uint8_t packet_source;
  uint8_t packet_type;
  uint8_t source_ip[16];
  uint16_t source_port;
  uint8_t dest_ip[16]; // 客户端使用 RELAY 服务器时注意，IPv6 加入时需要以 B 类 VERIFICATION 加入
  uint16_t dest_port;

  IPv4RelayHeader();
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

template <class T> struct IPv4RelayPacket {
  IPv4RelayHeader header;
  T raw_packet;

  uint8_t *data();
  const uint8_t *const_data() const;
};

template<class T>
uint8_t *IPv4RelayPacket<T>::data() {
  return reinterpret_cast<uint8_t *>(this);
}

template<class T>
const uint8_t *IPv4RelayPacket<T>::const_data() const {
  return reinterpret_cast<const uint8_t *>(this);
}

template <size_t size> uint8_t *SimplePacket<size>::data() {
  return reinterpret_cast<uint8_t *>(this);
}

template <size_t size> const uint8_t *SimplePacket<size>::const_data() const {
  return reinterpret_cast<const uint8_t *>(this);
}

} // namespace ra

#endif // OMELET_SRC_LINUX_BASE_PACKET_HPP
