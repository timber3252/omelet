//
// Created by timber3252 on 7/19/19.
//

#include "../../base/linux/aes.h"
#include "../../base/linux/global.h"
#include "../../base/linux/log.h"
#include "../../base/linux/router.h"
#include "../../base/linux/thread_safe.h"

ConsoleLog logc;
ipv4_address_t local_address_n, server_address_n, local_virtual_ip_n,
    local_application_request_ip_n;
port_t local_port_n, server_port_n, local_application_request_port_n;
sockfd_t sockfd;
Counter packet_id;
Router router;
Set virtual_ips;
std::mutex router_update, verification;
int tun_fd, nread;
char tun_name[IFNAMSIZ];
volatile bool need_verification, is_update_routers;

void init_socket() {
  sockfd = socket(PF_INET, SOCK_DGRAM, 0);

  if (sockfd < 0) {
    logc(LogLevel::Fatal) << "Failed to create socket object (errno = " << errno
                          << ")";
    exit(-1);
  }

  sockaddr_in addr{};
  addr.sin_family = PF_INET;
  addr.sin_port = local_port_n;
  addr.sin_addr.s_addr = local_address_n;

  if (bind(sockfd, (sockaddr *)&addr, sizeof addr) == -1) {
    logc(LogLevel::Fatal) << "Failed to bind ip address (errno = " << errno
                          << ")";
    exit(-1);
  }

  logc(LogLevel::Info) << "Client was started on " << inet_ntoa(addr.sin_addr)
                       << ':' << ntohs(addr.sin_port);
}

int tun_alloc(char *dev, int flags) {
  assert(dev != nullptr);

  ifreq ifr{};
  int fd, err;
  const char *tundev = "/dev/net/tun";

  if ((fd = open(tundev, O_RDWR)) < 0) {
    return fd;
  }

  memset(&ifr, 0, sizeof ifr);
  ifr.ifr_flags = flags;

  if (*dev != '\0') {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }
  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

int set_host_addr(const char *dev, int virtual_ip) {
  ifreq ifr{};
  bzero(&ifr, sizeof(ifr));
  strcpy(ifr.ifr_name, dev);

  sockaddr_in addr{};
  bzero(&addr, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = virtual_ip;
  bcopy(&addr, &ifr.ifr_addr, sizeof addr);

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    return -1;
  }

  if (ioctl(sockfd, SIOCSIFADDR, (void *)&ifr) < 0) {
    perror("ioctl SIOCSIFADDR");
    return -2;
  }

  if (ioctl(sockfd, SIOCGIFFLAGS, (void *)&ifr) < 0) {
    perror("ioctl SIOCGIFFLAGS");
    return -3;
  }

  ifr.ifr_flags |= IFF_UP;
  if (ioctl(sockfd, SIOCSIFFLAGS, (void *)&ifr) < 0) {
    perror("ioctl SIOCSIFFLAGS");
    return -4;
  }

  inet_pton(AF_INET, "255.0.0.0", &addr.sin_addr);
  bcopy(&addr, &ifr.ifr_netmask, sizeof addr);
  if (ioctl(sockfd, SIOCSIFNETMASK, (void *)&ifr) < 0) {
    perror("ioctl SIOCSIFNETMASK");
    return -5;
  }

  close(sockfd);
  return 0;
}

// 心跳包的定时发送，由于本身无连接，丢包可以忽略
void *do_heartbeat(void *) {
  OmeletProtoHeader header;
  header.set(packet_id.add(), PACKET_SERVER,
             PACKET_TYPE_HEARTBEAT | PACKET_NEED_REPLY, sizeof header,
             local_virtual_ip_n);
  auto *dbuf = new uint8_t[kAesBlockSize];
  aes_encrypt(reinterpret_cast<const uint8_t *>(&header), header.length,
              aes_key, dbuf);

  sockaddr_in addr{};
  addr.sin_family = PF_INET;
  addr.sin_port = server_port_n;
  addr.sin_addr.s_addr = server_address_n;

  socklen_t addr_len = sizeof(sockaddr_in);

  while (true) {
    sendto(sockfd, dbuf, header.length, 0, (sockaddr *)&addr, addr_len);
    sleep(5);
  }

  pthread_exit(nullptr);
}

void *resolve_packet_from_peer(void *p) {
  auto arg = (std::pair<Packet<kALBufferSize> *, sockaddr_in> *)p;
  uint8_t type = arg->first->header.packet_type;
  socklen_t addr_len = sizeof(sockaddr_in);
  //  auto *sendout = new uint8_t[kALBufferSize];

  if ((type & PACKET_NEED_REPLY) > 0) {
    type &= PACKET_UNIQUE_OPERATION;

  } else if ((type & PACKET_NO_REPLY) > 0) {
    type &= PACKET_UNIQUE_OPERATION;

    switch (type) {
      // 获取到的 IP 包直接写入 TUN 设备
      case PACKET_TYPE_RAW_IP_PACKET: {
        int nwrite =
            write(tun_fd, arg->first->data,
                  arg->first->header.length - sizeof(arg->first->header));
        break;
      }
    }
  }

  //  delete[] sendout;
  delete arg;
  pthread_exit(nullptr);
}

void *resolve_packet_from_server(void *p) {
  auto arg = (std::pair<Packet<kALBufferSize> *, sockaddr_in> *)p;
  uint8_t type = arg->first->header.packet_type;
  socklen_t addr_len = sizeof(sockaddr_in);
  auto *sendout = new uint8_t[kALBufferSize];

  if ((type & PACKET_NEED_REPLY) > 0) {
    type &= PACKET_UNIQUE_OPERATION;

    switch (type) {
      // 路由反馈，主动更新并发送回复，可以多次重复（客户端数量有上限），可以保证效率
      case PACKET_TYPE_GET_ROUTERS: {
        logc(LogLevel::Info) << "Received GET_ROUTERS reply from server";

        router.update_all(
            arg->first->data,
            arg->first->header.length - sizeof(arg->first->header),
            virtual_ips);

        router_update.lock();
        if (is_update_routers != 0) {
          is_update_routers = 0;
        }
        router_update.unlock();

        arg->first->header.set(arg->first->header.packet_id, PACKET_SERVER,
                               PACKET_TYPE_GET_ROUTERS | PACKET_NO_REPLY,
                               sizeof(arg->first->header), local_virtual_ip_n);
        aes_encrypt(reinterpret_cast<const uint8_t *>(arg->first),
                    arg->first->header.length, aes_key, sendout);
        sendto(sockfd, sendout,
               (size_t)ceil(arg->first->header.length / (double)kAesBlockSize) *
                   kAesBlockSize,
               0, (sockaddr *)&(arg->second), addr_len);

        break;
      }

      // 若服务器未能及时收到反馈，第二次及以后收到这个数据包则只回复，不做其他操作
      case PACKET_TYPE_VERIFICATION: {
        logc(LogLevel::Info) << "Received VERIFICATION reply from server";

        if (need_verification) {
          union {
            ipv4_address_t i;
            uint8_t s[4];
          } virtual_ip;

          memcpy(virtual_ip.s, arg->first->data, sizeof virtual_ip.s);
          local_virtual_ip_n = virtual_ip.i;
          virtual_ips.insert(local_virtual_ip_n);
        }
        arg->first->header.set(arg->first->header.packet_id, PACKET_SERVER,
                               PACKET_TYPE_VERIFICATION | PACKET_NO_REPLY,
                               sizeof(arg->first->header), local_virtual_ip_n);
        aes_encrypt(reinterpret_cast<const uint8_t *>(arg->first),
                    arg->first->header.length, aes_key, sendout);
        sendto(sockfd, sendout,
               (size_t)ceil(arg->first->header.length / (double)kAesBlockSize) *
                   kAesBlockSize,
               0, (sockaddr *)&(arg->second), addr_len);

        verification.lock();
        need_verification = false;
        verification.unlock();
        break;
      }
    }
  } else if ((type & PACKET_NO_REPLY) > 0) {
    type &= PACKET_UNIQUE_OPERATION;

    switch (type) {
      // 收到握手请求则立即进行握手操作，不考虑丢包问题
      case PACKET_TYPE_HANDSHAKE_REQUEST: {
        logc(LogLevel::Info) << "Received HANDSHAKE request from server "
                             << arg->first->header.virtual_ip_n;

        Peer dest;
        memcpy(&dest, arg->first->data,
               arg->first->header.length - sizeof(arg->first->header.length));

        sockaddr_in dest_addr{};
        dest_addr.sin_family = PF_INET;
        dest_addr.sin_port = dest.port_n;
        dest_addr.sin_addr.s_addr = dest.ip_n;

        socklen_t dest_addr_len = sizeof(sockaddr_in);

        arg->first->header.set(packet_id.add(), PACKET_PEERS,
                               PACKET_TYPE_HANDSHAKE | PACKET_NO_REPLY,
                               sizeof(arg->first->header), local_virtual_ip_n);
        aes_encrypt(reinterpret_cast<const uint8_t *>(arg->first),
                    arg->first->header.length, aes_key, sendout);
        sendto(sockfd, sendout,
               (size_t)ceil(arg->first->header.length / (double)kAesBlockSize) *
                   kAesBlockSize,
               0, (sockaddr *)&dest_addr, dest_addr_len);

        break;
      }
    }
  }

  delete arg;
  delete[] sendout;
  pthread_exit(nullptr);
}

// 接收消息的主循环，异步处理，避免阻塞导致丢包
void *receive_packet(void *) {
  uint8_t buf[kALBufferSize], dbuf[kALBufferSize];
  sockaddr_in peer_addr{};
  socklen_t peer_addr_len = sizeof(sockaddr_in);

  while (true) {
    int nrecv = recvfrom(sockfd, buf, kALBufferSize, 0, (sockaddr *)&peer_addr,
                         &peer_addr_len);

    if (nrecv < 0) {
      continue;
    }

    if (aes_decrypt(buf, nrecv, aes_key, dbuf) < 0) {
      continue;
    }

    auto *arg = new std::pair<Packet<kALBufferSize> *, sockaddr_in>();

    memcpy(&(arg->first->header), dbuf, sizeof(arg->first->header));
    memcpy(arg->first->data, dbuf + sizeof(arg->first->header),
           nrecv - sizeof(arg->first->header));
    arg->second = peer_addr;

    if (arg->first->header.packet_source == PACKET_SERVER) {
      pthread_t tid;
      pthread_create(&tid, nullptr, resolve_packet_from_server, (void *)arg);
    } else if (arg->first->header.packet_source == PACKET_PEERS) {
      pthread_t tid;
      pthread_create(&tid, nullptr, resolve_packet_from_peer, (void *)arg);
    }

    memset(buf, 0x00, sizeof buf);
  }
}

// 异步等待路由表更新，如果能够找到对应的物理地址和端口，则把数据包发送出去，无需考虑握手问题
void *wait_and_send(void *p) {
  auto arg = (std::pair<Packet<kALBufferSize> *, ipv4_address_t> *)p;
  uint8_t type = arg->first->header.packet_type;
  socklen_t addr_len = sizeof(sockaddr_in);
  auto *sendout = new uint8_t[kALBufferSize];
  aes_encrypt(reinterpret_cast<const uint8_t *>(arg->first),
              arg->first->header.length, ::aes_key, sendout);

  for (int i = 0; i < 20; ++i) {
    auto res = router.query(arg->second);
    if (res != nullptr) {
      sockaddr_in peer_addr{};
      peer_addr.sin_family = PF_INET;
      peer_addr.sin_port = res->port;
      peer_addr.sin_addr.s_addr = res->ip;
      socklen_t peer_addr_len = sizeof(sockaddr_in);

      sendto(sockfd, sendout,
             ceil(arg->first->header.length / (double)kAesBlockSize) *
                 kAesBlockSize,
             0, (sockaddr *)&peer_addr, peer_addr_len);
      break;
    }
    usleep(50000);
  }

  delete[] sendout;
  delete arg;
  pthread_exit(nullptr);
}

// 主动更新路由表
void *do_router_update(void *) {
  OmeletProtoHeader header;
  header.set(packet_id.add(), PACKET_SERVER,
             PACKET_TYPE_GET_ROUTERS | PACKET_NEED_REPLY, sizeof header,
             local_virtual_ip_n);
  auto *dbuf = new uint8_t[kAesBlockSize];
  aes_encrypt(reinterpret_cast<const uint8_t *>(&header), sizeof header,
              aes_key, dbuf);

  is_update_routers = 1;

  sockaddr_in addr{};
  addr.sin_family = PF_INET;
  addr.sin_port = server_port_n;
  addr.sin_addr.s_addr = server_address_n;

  socklen_t addr_len = sizeof(sockaddr_in);

  sendto(sockfd, dbuf, header.length, 0, (sockaddr *)&addr, addr_len);

  // 只发送一次，进行 1s 的等待，没有回复则放弃
  for (int i = 0; i < 20; ++i) {
    if (is_update_routers == 0) {
      break;
    }
    usleep(50000);
  }

  router_update.unlock();
  delete[] dbuf;
  pthread_exit(nullptr);
}

// 初次验证的尝试过程，在 1s
// 左右内完成，无效则退出，等待若干秒后的又一次尝试，不可过于频繁的尝试连接
int do_verification() {
  OmeletProtoHeader header;
  header.set(packet_id.add(), PACKET_SERVER,
             PACKET_TYPE_VERIFICATION | PACKET_NEED_REPLY, sizeof header,
             local_virtual_ip_n);
  auto *dbuf = new uint8_t[kAesBlockSize];
  aes_encrypt(reinterpret_cast<const uint8_t *>(&header), sizeof header,
              aes_key, dbuf);

  sockaddr_in addr{};
  addr.sin_family = PF_INET;
  addr.sin_port = server_port_n;
  addr.sin_addr.s_addr = server_address_n;

  socklen_t addr_len = sizeof(sockaddr_in);

  sendto(sockfd, dbuf, header.length, 0, (sockaddr *)&addr, addr_len);

  for (int i = 0; i < 20; ++i) {
    verification.lock();

    if (!need_verification) {
      verification.unlock();
      delete[] dbuf;
      return 0;
    }

    verification.unlock();
    usleep(50000);
  }

  delete[] dbuf;
  return -1;
}

// 主动离开，不保证可靠性，丢包则忽略
void do_leave(int signum) {
  OmeletProtoHeader header;
  header.set(packet_id.add(), PACKET_SERVER,
             PACKET_TYPE_LEAVE | PACKET_NO_REPLY, sizeof header,
             local_virtual_ip_n);
  auto *dbuf = new uint8_t[kAesBlockSize];
  aes_encrypt(reinterpret_cast<const uint8_t *>(&header), sizeof header,
              aes_key, dbuf);

  sockaddr_in addr{};
  addr.sin_family = PF_INET;
  addr.sin_port = server_port_n;
  addr.sin_addr.s_addr = server_address_n;
  socklen_t addr_len = sizeof(sockaddr_in);

  sendto(sockfd, dbuf, header.length, 0, (sockaddr *)&addr, addr_len);
  close(sockfd);

  logc(LogLevel::Info) << "Client received signal " << signum
                       << " and leaved from the server";
}

void *local_service_sub(void *p) {
  int fd = *static_cast<int *>(p), self;
  sockaddr_in peer_sa{};
  socklen_t peer_sa_len = sizeof peer_sa;
  getpeername(fd, (sockaddr *)&peer_sa, &peer_sa_len);
  auto *sp = new SimplePacket<kALBufferSize>();

  while (true) {
    memset(sp->data, 0x00, sizeof sp->data);
    int nrecv = recv(fd, &sp, kALBufferSize, 0);

    if (nrecv <= 0 || sp->header.packet_source != PACKET_APPLICATIONS) {
      logc(LogLevel::Info) << "Application " << fd << " has disconnected";

      close(fd);
      pthread_exit(nullptr);
    }

    int type = sp->header.packet_type;
    if ((type & PACKET_NEED_REPLY) > 0) {
      type &= PACKET_UNIQUE_OPERATION;
      switch (type) {
        case PACKET_TYPE_LOCAL_GET_ROUTERS: {
          if (router_update.try_lock()) {
            pthread_t tid_21;
            pthread_create(&tid_21, nullptr, do_router_update, nullptr);
          }
          int nquery = virtual_ips.query_all(sp->data);
          sp->header.set(PACKET_APPLICATIONS,
                         PACKET_TYPE_LOCAL_GET_ROUTERS | PACKET_NO_REPLY,
                         sizeof(sp->header) + nquery);
          send(fd, sp, sp->header.length, 0);
          break;
        }

        case PACKET_TYPE_LOCAL_GET_VIRTUAL_IP: {
          sp->header.set(PACKET_APPLICATIONS,
                         PACKET_TYPE_LOCAL_GET_VIRTUAL_IP | PACKET_NO_REPLY,
                         sizeof(sp->header) + sizeof(ipv4_address_t));
          memcpy(sp->data, &local_virtual_ip_n, sizeof local_virtual_ip_n);
          send(fd, sp, sp->header.length, 0);
          break;
        }
      }

    } else if ((type & PACKET_NO_REPLY) > 0) {
      type &= PACKET_UNIQUE_OPERATION;
    }
  }

  pthread_exit(nullptr);
}

void *local_service(void *) {
  // 本机监听，使用有连接 socket
  int local_service_sockfd;
  sockaddr_in local_application_request_addr{};
  local_application_request_addr.sin_family = PF_INET;
  local_application_request_addr.sin_port = local_application_request_port_n;
  local_application_request_addr.sin_addr.s_addr =
      local_application_request_ip_n;

  if (bind(local_service_sockfd, (sockaddr *)&local_application_request_addr,
           sizeof local_application_request_addr) == -1) {
    logc(LogLevel::Fatal) << "(Local Service) Failed to bind ip address.";
    exit(-1);
  }

  if (listen(local_service_sockfd, kMaxConnections) == -1) {
    logc(LogLevel::Fatal) << "(Local Service) Failed to listen on "
                          << inet_ntoa(local_application_request_addr.sin_addr)
                          << ':'
                          << ntohs(local_application_request_addr.sin_port);
    exit(-1);
  }

  // 等待上层应用加入，不记录
  while (true) {
    sockaddr_in peer{};
    socklen_t peer_len = sizeof peer;
    int fd = accept(local_service_sockfd, (sockaddr *)&peer, &peer_len);
    if (fd == -1) {
      logc(LogLevel::Error)
          << "Failed to accept client. (errno = " << errno << ")";
      continue;
    }

    logc(LogLevel::Info) << "Application " << fd
                         << " has connected to the client";

    // 创建子线程与应用程序交互
    pthread_t tid_15;
    pthread_create(&tid_15, nullptr, local_service_sub, &fd);
  }

  pthread_exit(nullptr);
}

int main(int argc, char *argv[]) {
  int ch;
  // 此处的常数均是以网络字节顺序而定的，而非字节顺序，修改时要注意
  server_port_n = 33106, server_address_n = 0;
  local_port_n = 1168, local_address_n = 0;
  local_application_request_port_n = 48978;
  local_application_request_ip_n = 16777343;

  while ((ch = getopt(argc, argv, "hl:k:s:b:")) != -1) {
    switch (ch) {
      case 'h': {
        printf(
            "Usage: %s arguments ..                                            "
            "      \n"
            "  -h           show help                                          "
            "      \n"
            "  -l addr      set local address (default = 0.0.0.0:36868)        "
            "      \n"
            "  -k aes_key   use specific aes key (length = 128)                "
            "      \n"
            "  -s addr      set server address (default = 0.0.0.0:21121)       "
            "      \n"
            "  -b addr      application request service (default = "
            "127.0.0.1:21183)  \n",
            argv[0]);
        return 0;
      }

      case 'l': {
        std::string local_address(optarg);
        int pos = local_address.find(':');
        local_address_n = inet_addr(local_address.substr(0, pos).c_str());
        local_port_n = htons(std::stoi(local_address.substr(pos + 1)));

        if (local_address_n == 0xffffffff || local_port_n == 0) {
          logc(LogLevel::Fatal) << "Invalid local address: " << local_address;
          exit(-1);
        }

        break;
      }

      case 'k': {
        FILE *fo = fopen(optarg, "r");

        if (fo == nullptr) {
          logc(LogLevel::Fatal) << "File " << optarg << " does not exist";
          exit(-1);
        }

        memset(aes_key, 0x00, sizeof aes_key);
        int nread = fread(aes_key, sizeof(uint8_t), kAesKeyLength, fo);

        if (nread != kAesKeyLength) {
          logc(LogLevel::Fatal)
              << "File " << optarg << " does not contain valid aes key";
          exit(-1);
        }

        break;
      }

      case 's': {
        std::string server_address(optarg);
        int pos = server_address.find(':');
        server_address_n = inet_addr(server_address.substr(0, pos).c_str());
        server_port_n = htons(std::stoi(server_address.substr(pos + 1)));

        if (server_address_n == 0xffffffff || server_port_n == 0) {
          logc(LogLevel::Fatal) << "Invalid server address: " << server_address;
          exit(-1);
        }

        break;
      }

      case 'b': {
        std::string local_application_request(optarg);
        int pos = local_application_request.find(':');
        local_application_request_ip_n =
            inet_addr(local_application_request.substr(0, pos).c_str());
        local_application_request_port_n =
            htons(std::stoi(local_application_request.substr(pos + 1)));

        if (local_application_request_ip_n == 0xffffffff ||
            local_application_request_port_n == 0) {
          logc(LogLevel::Fatal)
              << "Invalid server address: " << local_application_request;
          exit(-1);
        }

        break;
      }
    }
  }

  init_socket();

  pthread_t tid_1;
  pthread_create(&tid_1, nullptr, receive_packet, nullptr);

  // 主动退出
  signal(SIGKILL, do_leave);
  signal(SIGINT, do_leave);

  // 确保 VERIFICATION 包绝对可靠接收
  int secs = 1, nverify = 0;
  while (true) {
    logc(LogLevel::Info) << "Attempt to connect to the server: attempt"
                         << ++nverify;
    if (!do_verification()) {
      logc(LogLevel::Info) << "Successfully connected to the server";
      break;
    }
    logc(LogLevel::Info) << "Retry in " << secs << " seconds";
    sleep(secs);
    secs = std::min(15, secs * 2);
  }

  // 与上层应用程序交互，使用 TCP
  pthread_t tid_18;
  pthread_create(&tid_18, nullptr, local_service, nullptr);

  pthread_t tid_2;
  pthread_create(&tid_2, nullptr, do_heartbeat, nullptr);

  // 创建 TUN 设备
  tun_name[0] = '\0';
  tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
  if (tun_fd < 0) {
    logc(LogLevel::Fatal) << "Failed to allocate interface.";
    exit(-1);
  }
  logc(LogLevel::Info) << "Open tun device: " << tun_name << " for reading.";

  // 设置 TUN 设备虚拟地址
  int ret = set_host_addr(tun_name, local_virtual_ip_n);
  if (ret < 0) {
    logc(LogLevel::Fatal) << "Failed to set address of tun device. (errcode = "
                          << ret << ")";
    exit(-1);
  }

  struct TempData {
    OmeletProtoHeader header;
    uint8_t buffer[kNLBufferSize];
  } buf;

  auto *dbuf = new uint8_t[kALBufferSize];

  sockaddr_in server_addr{};
  server_addr.sin_family = PF_INET;
  server_addr.sin_port = server_port_n;
  server_addr.sin_addr.s_addr = server_address_n;

  socklen_t server_addr_len = sizeof(sockaddr_in);

  // 从 TUN 设备读取 IP 数据包，格式为 IP 头部 + (TCP / UDP / ICMP 等协议头部) +
  // 内容
  while (true) {
    memset(buf.buffer, 0x00, sizeof buf.buffer);
    nread = read(tun_fd, buf.buffer, kNLBufferSize);
    if (nread < 0) {
      logc(LogLevel::Error) << "Failed to read from interface.";
      close(tun_fd);
      exit(-1);
    }

    union {
      ipv4_address_t i;
      uint8_t s[4];
    } dest_ip_n;

    // 根据 IPv4 数据包头部，取 16 ~ 19 字节为目标 IP，实则虚拟 IP 地址
    dest_ip_n.s[0] = buf.buffer[16];
    dest_ip_n.s[1] = buf.buffer[17];
    dest_ip_n.s[2] = buf.buffer[18];
    dest_ip_n.s[3] = buf.buffer[19];

    // 保证效率，舍弃一定不符合虚拟 IP 规则的数据包
    if (dest_ip_n.s[0] == 0x0a) {
      continue;
    }

    // 发送握手请求，可以多次发送，但对方不响应
    buf.header.set(packet_id.add(), PACKET_SERVER,
                   PACKET_TYPE_HANDSHAKE_REQUEST | PACKET_NO_REPLY,
                   sizeof(buf.header) + 4, local_virtual_ip_n);
    memcpy(buf.buffer, dest_ip_n.s, sizeof dest_ip_n.s);
    aes_encrypt(reinterpret_cast<const uint8_t *>(&buf), buf.header.length,
                aes_key, dbuf);

    sendto(sockfd, dbuf,
           ceil(buf.header.length / (double)kAesBlockSize) * kAesBlockSize, 0,
           (sockaddr *)&server_addr, server_addr_len);

    // 转发数据包
    auto res = router.query(dest_ip_n.i);

    if (res == nullptr) {
      // 不存在该虚拟 IP
      // 对应的地址，则尝试获取更新，但禁止多个线程同时获取路由表更新
      // 因而此处使用了非阻塞的互斥锁行为
      if (router_update.try_lock()) {
        pthread_t tid_20;
        pthread_create(&tid_20, nullptr, do_router_update, nullptr);
      }

      auto *arg = new std::pair<Packet<kALBufferSize> *, ipv4_address_t>();

      arg->first->header.set(packet_id.add(), PACKET_PEERS,
                             PACKET_TYPE_RAW_IP_PACKET | PACKET_NO_REPLY,
                             sizeof(OmeletProtoHeader) + nread,
                             local_virtual_ip_n);
      memcpy(arg->first->data, buf.buffer, nread);
      arg->second = dest_ip_n.i;

      // 并且创建异步等待线程，有效时长
      // 1s，在有效时长内，更新完成，能够找到对应的物理地址则发送，否则放弃
      pthread_t tid_19;
      pthread_create(&tid_19, nullptr, wait_and_send, arg);
      continue;
    }

    aes_encrypt(reinterpret_cast<const uint8_t *>(&buf), buf.header.length,
                aes_key, dbuf);

    sockaddr_in peer_addr{};
    peer_addr.sin_family = PF_INET;
    peer_addr.sin_port = res->port;
    peer_addr.sin_addr.s_addr = res->ip;
    socklen_t peer_addr_len = sizeof(sockaddr_in);

    sendto(sockfd, dbuf,
           ceil(buf.header.length / (double)kAesBlockSize) * kAesBlockSize, 0,
           (sockaddr *)&peer_addr, peer_addr_len);
  }
}