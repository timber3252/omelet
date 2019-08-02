//
// Created by timber3252 on 7/30/19.
//

#ifndef OMELET_SRC_LINUX_BASE_GLOBAL_HPP
#define OMELET_SRC_LINUX_BASE_GLOBAL_HPP

#include "include.hpp"

#include "address.hpp"
#include "aes.hpp"
#include "log.hpp"
#include "packet.hpp"
#include "r_map.hpp"

const int kMaxConnections = 500;

#define PACKET_FROM_CLIENT 0xd1
#define PACKET_FROM_SERVER 0xd2
#define PACKET_FROM_APP 0xd3
#define PACKET_FROM_API 0xd4
#define PACKET_FROM_PEERS 0xd5

//#define PACKET_HEARTBEAT                  0x01
//#define PACKET_HANDSHAKE                  0x02
#define PACKET_GET_ROUTERS 0x03
#define PACKET_VERIFICATION 0x04
#define PACKET_RAW_IP_PACKET 0x05
#define PACKET_LEAVE 0x06
//#define PACKET_HANDSHAKE_REQUEST          0x07
#define PACKET_LOCAL_GET_ROUTERS 0x08
#define PACKET_LOCAL_GET_VIRTUAL_IP 0x09
#define PACKET_SERVER_CLOSED 0x0a
#define PACKET_ERROR_SERVER_FULL 0x0b

#endif // OMELET_SRC_LINUX_BASE_GLOBAL_HPP
