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
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/aes.h>

const int kMaxConnections = 200;
const size_t kBufSize = 2048;
const size_t kMinBufSize = AES_BLOCK_SIZE;
const size_t kProtocolMaxSize = 72000;

#define PACKET_HEARTBEAT 0x01
#define PACKET_QUERY_NAT_SELF 0x02
#define PACKET_QUERY_CLIENT_LIST 0x03
#define PACKET_REG 0x04
#define PACKET_FIRST_CONFIRM 0x05

#endif // PROLINE_BACKEND_GLOBAL_H
