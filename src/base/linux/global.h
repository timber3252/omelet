//
// Created by timber3252 on 5/26/19.
//

#ifndef PROLINE_BACKEND_GLOBAL_H
#define PROLINE_BACKEND_GLOBAL_H

#include <cassert>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <regex>
#include <set>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/aes.h>

typedef int ipv4_address_t;
typedef int sockfd_t;
typedef uint16_t port_t;

const size_t kMaxConnections = 2000;
const size_t kALBufferSize = 65536;  // AL: Application Layer
const size_t kNLBufferSize = 2048;   // NL: Network Layer
const size_t kAesBlockSize = AES_BLOCK_SIZE;
const size_t kAesKeyLength = 128;

#define PACKET_SERVER 0xd1
#define PACKET_PEERS 0xd2
#define PACKET_APPLICATIONS 0xd3

#define PACKET_UNIQUE_OPERATION 0b00111111
#define PACKET_TYPE_HEARTBEAT 0b00000001          // c -> s
#define PACKET_TYPE_HANDSHAKE 0b00000010          // c -> c
#define PACKET_TYPE_GET_ROUTERS 0b00000011        // c -> s, must
#define PACKET_TYPE_VERIFICATION 0b00000100       // c -> s, must
#define PACKET_TYPE_RAW_IP_PACKET 0b00000101      // c -> c
#define PACKET_TYPE_LEAVE 0b00000110              // c -> s
#define PACKET_TYPE_HANDSHAKE_REQUEST 0b00000111  // c -> s then s -> c, ip
#define PACKET_TYPE_LOCAL_GET_ROUTERS 0b00001000
#define PACKET_TYPE_LOCAL_GET_VIRTUAL_IP 0b00001001
#define PACKET_NO_REPLY 0b01000000
#define PACKET_NEED_REPLY 0b10000000

struct OmeletProtoHeader {
  OmeletProtoHeader()
      : packet_id(0), packet_source(0), packet_type(0), length(0) {}

  uint32_t packet_id;
  uint8_t packet_source;
  uint8_t packet_type;
  uint16_t length;
  uint32_t virtual_ip_n;

  void set(int id, int source, int type, int len, int ip_n) {
    packet_id = id, packet_source = source, packet_type = type, length = len,
    virtual_ip_n = ip_n;
  }
};

struct OmeletSimpleProtoHeader {
  OmeletSimpleProtoHeader() : packet_source(0), packet_type(0), length(0) {}

  uint8_t packet_source;
  uint8_t packet_type;
  uint16_t length;

  void set(int source, int type, int len) {
    packet_source = source, packet_type = type, length = len;
  }
};

template <size_t size>
struct Packet {
  Packet() : header() { memset(data, 0x00, sizeof data); }

  OmeletProtoHeader header;
  uint8_t data[size];
};

template <size_t size>
struct SimplePacket {
  SimplePacket() : header() { memset(data, 0x00, sizeof data); }

  OmeletSimpleProtoHeader header;
  uint8_t data[size];
};

struct Peer {
  Peer() : ip_n(0), port_n(0) {}
  Peer(ipv4_address_t a, port_t p) : ip_n(a), port_n(p) {}

  ipv4_address_t ip_n;
  port_t port_n;
};

#endif  // PROLINE_BACKEND_GLOBAL_H
