//
// Created by timber3252 on 7/28/19.
//

#include "linux/base/global.hpp"

// TODO: 客户端可以为 IPv4 / IPv6

using ra::LogLevel;

ra::ConsoleLog logc;
ra::Endpoint local_addr, server_addr, api_addr;
ra::Address virtual_ip;
ra::RMap<ra::Address, ra::Endpoint> routers;
std::optional<ra::Endpoint> relay_addr{};

std::chrono::system_clock::time_point last_heartbeat;
int local_sockfd, api_sockfd;
volatile bool need_verification;

int tun_fd, nread;
char tun_name[IFNAMSIZ];

bool is_v4;

template <size_t size>
void relay_send(int fd, const ra::IPv4RelayPacket<ra::Packet<size>> &pack, ra::Endpoint ep) {
  auto *enc_pack = new uint8_t[size];
  int len = ra::aes_encrypt(pack.const_data(), pack.raw_packet.header.length + sizeof pack.header, ra::aes_key,
                            enc_pack);

  //  logc(LogLevel::Debug) << "send packet [" << int(pack.header.packet_source)
  //  << ", " << int(pack.header.packet_type) << ", " << pack.header.length <<
  //  "] to " << ep.address().to_string();

  sendto(fd, enc_pack, len, 0,
         reinterpret_cast<const sockaddr *>(&ep.raw_sockaddr()),
         sizeof ep.raw_sockaddr());

  delete[] enc_pack;
}

template <size_t size>
std::optional<ra::Endpoint> relay_recv(int fd, ra::IPv4RelayPacket<ra::Packet<size>> &pack) {
  auto *enc_pack = new uint8_t[size];
  sockaddr_in6 sender_addr{};
  socklen_t sender_addr_len = sizeof sender_addr;

  int nrecv = recvfrom(fd, enc_pack, size, 0, (sockaddr *)&sender_addr,
                       &sender_addr_len);

  if (nrecv < 0) {
    return {};
  }

  ra::aes_decrypt(enc_pack, nrecv, ra::aes_key, pack.data());

  //  logc(LogLevel::Debug) << "receive packet [" <<
  //  int(pack.header.packet_source) << ", " << int(pack.header.packet_type) <<
  //  ", " << pack.header.length << "] from " <<
  //  ra::Endpoint(sender_addr).address().to_string();

  return ra::Endpoint(sender_addr);
}

template <size_t size>
void omelet_send(int fd, const ra::Packet<size> &pack, ra::Endpoint ep) {
  if (is_v4) {
    auto *pack_relay = new ra::IPv4RelayPacket<ra::Packet<size>>();
    memcpy(pack_relay->raw_packet.data(), pack.const_data(), sizeof pack);

    pack_relay->header.protocol_id = PROTOCOL_RELAY;
    if (pack.header.packet_source == PACKET_FROM_CLIENT) {
      pack_relay->header.packet_type = PACKET_RELAY_RAW_TO_SERVER;
    } else if (pack.header.packet_source == PACKET_FROM_PEERS) {
      pack_relay->header.packet_type = PACKET_RELAY_RAW_TO_PEERS;
    }

    auto src_addr = local_addr.address().raw_bytes();
    std::copy(src_addr.begin(), src_addr.end(), pack_relay->header.source_ip);
    pack_relay->header.source_port = local_addr.port();

    auto dest_addr = ep.address().raw_bytes();
    std::copy(dest_addr.begin(), dest_addr.end(), pack_relay->header.dest_ip);
    pack_relay->header.dest_port = ep.port();

    relay_send(fd, *pack_relay, relay_addr.value());
  } else {
    auto *enc_pack = new uint8_t[size];
    int len = ra::aes_encrypt(pack.const_data(), pack.header.length, ra::aes_key,
                              enc_pack);

    //  logc(LogLevel::Info) << "send packet [" << int(pack.header.packet_source)
    //  << ", " << int(pack.header.packet_type) << ", " << pack.header.length <<
    //  "]";

    sendto(fd, enc_pack, len, 0,
           reinterpret_cast<const sockaddr *>(&ep.raw_sockaddr()),
           sizeof ep.raw_sockaddr());

    delete[] enc_pack;
  }
}

template <size_t size>
std::optional<ra::Endpoint> omelet_recv(int fd, ra::Packet<size> &pack) {
  auto *enc_pack = new uint8_t[size];
  sockaddr_in6 sender_addr{};
  socklen_t sender_addr_len = sizeof sender_addr;

  int nrecv = recvfrom(fd, enc_pack, size, 0, (sockaddr *)&sender_addr,
                       &sender_addr_len);

  if (nrecv < 0) {
    return {};
  }

  ra::aes_decrypt(enc_pack, nrecv, ra::aes_key, pack.data());

  //  logc(LogLevel::Debug) << "receive packet [" <<
  //  int(pack.header.packet_source) << ", " << int(pack.header.packet_type) <<
  //  ", " << pack.header.length << "] from " <<
  //  ra::Endpoint(sender_addr).address().to_string();

  return ra::Endpoint(sender_addr);
}

void init_socket() {
  local_sockfd = socket(AF_INET6, SOCK_DGRAM, 0);

  if (local_sockfd < 0) {
    logc(LogLevel::Fatal) << "failed to create socket object";
    logc(LogLevel::Fatal) << "last error code: " << errno;
    exit(-1);
  }

  if (bind(local_sockfd,
           reinterpret_cast<const sockaddr *>(&local_addr.raw_sockaddr()),
           sizeof local_addr.raw_sockaddr()) == -1) {
    logc(LogLevel::Fatal) << "failed to bind ip address (" << errno << ")";
    exit(-1);
  }

  logc(LogLevel::Info) << "client was started on ["
                       << local_addr.address().to_string()
                       << "]:" << local_addr.port();
}

void do_leave(int sig) {
  ra::Packet<OMELET_CMD_BUFFER_SIZE> pack;
  pack.header.set(PACKET_FROM_CLIENT, PACKET_LEAVE, sizeof pack.header,
                  virtual_ip.raw_bytes());

  omelet_send(local_sockfd, pack, server_addr);

  logc(LogLevel::Info) << "client stopped";
  exit(sig);
}

void do_verification() {
  ra::Packet<OMELET_CMD_BUFFER_SIZE> pack;
  pack.header.set(PACKET_FROM_CLIENT, PACKET_VERIFICATION, sizeof pack.header);

  omelet_send(local_sockfd, pack, server_addr);
}

void do_routers_update() {
  ra::Packet<OMELET_CMD_BUFFER_SIZE> pack;
  pack.header.set(PACKET_FROM_CLIENT, PACKET_GET_ROUTERS, sizeof pack.header,
                  virtual_ip.raw_bytes());

  while (true) {
    omelet_send(local_sockfd, pack, server_addr);

    std::this_thread::sleep_for(std::chrono::seconds(5));
  }
}

template <size_t size>
void handle_server_packet(const ra::Endpoint &sender,
                          ra::Packet<size> *pack) {
  uint8_t type = pack->header.packet_type;

  switch (type) {
  case PACKET_GET_ROUTERS: {
    int len = pack->header.length - sizeof pack->header;

    if (len % 34 == 0) {
      ra::RMap<ra::Address, ra::Endpoint> routers_new;

      for (int i = 0; i < len; i += 34) {
        ra::ipv6_address_t virt_ip, phy_ip;
        ra::port_t port;

        std::copy(pack->buf + i, pack->buf + i + 16, virt_ip.begin());
        std::copy(pack->buf + i + 16, pack->buf + i + 32, phy_ip.begin());
        port = pack->buf[i + 32] | (pack->buf[i + 33] << 8);

        ra::Address virt_addr(virt_ip);
        ra::Endpoint phy_ep(phy_ip, port);

        routers_new.insert(virt_addr, phy_ep);
      }

      routers.swap(routers_new);
    }
    break;
  }

  case PACKET_VERIFICATION: {
    ra::ipv6_address_t virt_ip;
    std::copy(pack->buf, pack->buf + 16, virt_ip.begin());

    ::virtual_ip = ra::Address(virt_ip);
    need_verification = false;

    logc(LogLevel::Info) << "allocated virtual ip: " << virtual_ip.to_string();

    break;
  }

  case PACKET_SERVER_CLOSED: {
    logc(LogLevel::Info) << "server has closed";
    do_leave(0);
    break;
  }

  case PACKET_ERROR_SERVER_FULL: {
    logc(LogLevel::Error) << "server was full";
    do_leave(0);
    break;
  }
  }
}

template <size_t size>
void handle_peer_packet(const ra::Endpoint &sender,
                        ra::Packet<size> *pack) {
  // TODO: handle peer packet
  uint8_t type = pack->header.packet_type;

  switch (type) {
  case PACKET_RAW_IP_PACKET: {
    int nwrite =
        write(tun_fd, pack->buf, pack->header.length - sizeof pack->header);

    if (nwrite < 0) {
      logc(LogLevel::Error)
          << "failed to write data to " << tun_name << " (" << errno << ")";
      break;
    }

    //    logc(LogLevel::Info) << "write " << nwrite << " bytes to " <<
    //    tun_name;

    break;
  }
  }
}

int tun_alloc(char *dev, int flags) {
  assert(dev != nullptr);

  ifreq ifr{};
  int fd, err;
  const char *tundev = "/dev/net/tun";

  if ((fd = open(tundev, O_RDWR)) < 0) {
    return fd;
  }

  memset(&ifr, 0x00, sizeof ifr);
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

int set_host_addr6(char *dev, in6_ifreq ifreq6) {
  int sockfd6;
  struct ifreq ifr;

  if ((sockfd6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
    logc(LogLevel::Fatal) << "failed to create socket object";
    do_leave(-1);
  }

  strcpy(ifr.ifr_name, dev);
  ioctl(sockfd6, SIOCGIFINDEX, &ifr);
  ifreq6.ifr6_ifindex = ifr.ifr_ifindex;

  if (ioctl(sockfd6, SIOCSIFADDR, &ifreq6) < 0) {
    perror("ioctl SIOCSIFADDR");
    do_leave(-1);
  }

  if (ioctl(sockfd6, SIOCGIFFLAGS, (void *)&ifr) < 0) {
    perror("ioctl SIOCGIFFLAGS");
    do_leave(-1);
  }

  ifr.ifr_flags |= IFF_UP;
  if (ioctl(sockfd6, SIOCSIFFLAGS, (void *)&ifr) < 0) {
    perror("ioctl SIOCSIFFLAGS");
    do_leave(-1);
  }

  return 0;
}

void do_recv() {
  while (true) {
    auto *pack(new ra::Packet<OMELET_AL_BUFFER_SIZE>);
    auto sender = omelet_recv(local_sockfd, *pack);

    if (sender.has_value()) {
      if (pack->header.protocol_id == PROTOCOL_OMELET) {
        if (pack->header.packet_source == PACKET_FROM_SERVER) {
          std::thread resolve_thread(handle_server_packet<OMELET_AL_BUFFER_SIZE>,
                                     sender.value(), pack);
          resolve_thread.detach();
        } else if (pack->header.packet_source == PACKET_FROM_PEERS) {
          std::thread resolve_thread(handle_peer_packet<OMELET_AL_BUFFER_SIZE>,
                                     sender.value(), pack);
          resolve_thread.detach();
        }
      } else {
        auto *pack_relay = new ra::IPv4RelayPacket<ra::Packet<OMELET_AL_BUFFER_SIZE>>();
        memcpy(pack_relay->data(), pack->data(), OMELET_AL_BUFFER_SIZE);

        ra::ipv6_address_t a;
        std::copy(pack_relay->header.source_ip, pack_relay->header.source_ip + 16, a.begin());
        ra::Endpoint ep(a, pack_relay->header.source_port);

        if (pack_relay->raw_packet.header.packet_source == PACKET_FROM_SERVER) {
          std::thread resolve_thread(handle_server_packet<OMELET_AL_BUFFER_SIZE>,
                                     ep, &pack_relay->raw_packet);
          resolve_thread.detach();
        } else if (pack_relay->raw_packet.header.packet_source == PACKET_FROM_PEERS) {
          std::thread resolve_thread(handle_peer_packet<OMELET_AL_BUFFER_SIZE>,
                                     ep, &pack_relay->raw_packet);
          resolve_thread.detach();
        }
        delete pack;
      }
    }
  }
}

void handle_api_service(int fd) {
  while (true) {
    ra::SimplePacket<OMELET_CMD_BUFFER_SIZE> pack;
    int nrecv = recv(fd, pack.data(), OMELET_CMD_BUFFER_SIZE, 0);

    if (nrecv <= 0) {
      logc(LogLevel::Info) << "application " << fd
                           << " has ended api service connection";

      close(fd);
      return;
    }

    if (pack.header.packet_source == PACKET_FROM_APP) {
      switch (pack.header.packet_type) {
      case PACKET_LOCAL_GET_ROUTERS: {
        ra::SimplePacket<OMELET_AL_BUFFER_SIZE> reply;
        reply.header.set(PACKET_FROM_API, PACKET_LOCAL_GET_ROUTERS,
                         sizeof reply.header);

        routers.query_all<ra::SimplePacket<OMELET_AL_BUFFER_SIZE>>(
            reply, [](const ra::Address &first, const ra::Endpoint &second,
                      ra::SimplePacket<OMELET_AL_BUFFER_SIZE> &reply) {
              auto raw_addr = first.raw_bytes();
              std::copy(raw_addr.begin(), raw_addr.end(),
                        reply.data() + reply.header.length);
              reply.header.length += raw_addr.size();
            });

        send(fd, reply.data(), reply.header.length, 0);
        break;
      }

      case PACKET_LOCAL_GET_VIRTUAL_IP: {
        ra::SimplePacket<OMELET_CMD_BUFFER_SIZE> reply;
        reply.header.set(PACKET_FROM_API, PACKET_LOCAL_GET_VIRTUAL_IP,
                         sizeof reply.header + 16);
        auto raw_addr = virtual_ip.raw_bytes();
        std::copy(raw_addr.begin(), raw_addr.end(), reply.buf);

        send(fd, reply.data(), reply.header.length, 0);
        break;
      }
      }
    }
  }
}

void serve_local_api() {
  api_sockfd = socket(AF_INET6, SOCK_STREAM, 0);

  int on = 1;
  setsockopt(api_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  if (bind(api_sockfd,
           reinterpret_cast<const sockaddr *>(&api_addr.raw_sockaddr()),
           sizeof api_addr.raw_sockaddr()) == -1) {
    logc(LogLevel::Fatal) << "failed to bind ip address (" << errno << ")";
    exit(-1);
  }

  if (listen(api_sockfd, kMaxConnections) == -1) {
    logc(LogLevel::Fatal) << "failed to listen on ["
                          << api_addr.address().to_string()
                          << "]:" << api_addr.port();
    exit(-1);
  }

  while (true) {
    sockaddr_in6 peer{};
    socklen_t peer_len = sizeof peer;

    int fd = accept(api_sockfd, (sockaddr *)&peer, &peer_len);

    if (fd == -1) {
      logc(LogLevel::Error) << "failed to accept client (" << errno << ")";
      continue;
    }

    logc(LogLevel::Info) << "application " << fd
                         << " has connected to the api service";

    std::thread api_service_thread(handle_api_service, fd);
    api_service_thread.detach();
  }
}

void do_relay_heartbeat() {
  auto *pack = new ra::IPv4RelayPacket<ra::Packet<OMELET_AL_BUFFER_SIZE>>;
  pack->header.protocol_id = PROTOCOL_RELAY;
  pack->header.packet_type = PACKET_RELAY_HEARTBEAT;

  while (true) {
    relay_send(local_sockfd, *pack, relay_addr.value());

    std::this_thread::sleep_for(std::chrono::seconds(15));
  }
}

int main(int argc, char *argv[]) {
  int ch;

  local_addr = ra::Endpoint("[::]:36868");
  server_addr = ra::Endpoint("[::]:21121");
  api_addr = ra::Endpoint("[::]:21183");

  is_v4 = false;

  while ((ch = getopt(argc, argv, "hl:k:s:b:r:")) != -1) {
    switch (ch) {
    case 'h': {
      printf("Usage: %s arguments                                        \n"
             "  -h           show help                                   \n"
             "  -l addr      set local address (default = [::]:36868)    \n"
             "  -k aes_key   use specific aes key (length = 128)         \n"
             "  -s addr      set server address (default = [::]:21121)   \n"
             "  -b addr      api service (default = [::]:21183)          \n"
             "  -r addr      use relay server (optional)                 \n",
             argv[0]);
      return 0;
    }

    case 'l': {
      local_addr = ra::Endpoint(optarg);
      break;
    }

    case 'k': {
      FILE *fo = fopen(optarg, "r");

      if (fo == nullptr) {
        logc(LogLevel::Fatal) << "file " << optarg << " does not exist";
        exit(-1);
      }

      memset(ra::aes_key, 0x00, sizeof ra::aes_key);
      int nread =
          fread(ra::aes_key, sizeof(uint8_t), OMELET_AES_KEY_LENGTH, fo);

      if (nread != OMELET_AES_KEY_LENGTH) {
        logc(LogLevel::Fatal)
            << "file " << optarg << " does not contain valid aes key";
        exit(-1);
      }

      break;
    }

    case 's': {
      server_addr = ra::Endpoint(optarg);
      break;
    }

    case 'b': {
      api_addr = ra::Endpoint(optarg);
      break;
    }

    case 'r': {
      relay_addr = ra::Endpoint(optarg);
      break;
    }

    default: {
      break;
    }
    }
  }

  init_socket();

  if (relay_addr.has_value()) {
    auto *pack = new ra::IPv4RelayPacket<ra::Packet<OMELET_AL_BUFFER_SIZE>>;
    pack->header.protocol_id = PROTOCOL_RELAY;
    pack->header.packet_type = PACKET_RELAY_VERIFICATION;

    if (local_addr.address().is_v6()) {
      pack->header.packet_source = PACKET_RELAY_FROM_IPV6_CLIENT;
    } else {
      pack->header.packet_source = PACKET_RELAY_FROM_IPV4_CLIENT;
    }

    auto addr = local_addr.address().raw_bytes();
    std::copy(addr.begin(), addr.end(), pack->header.source_ip);
    pack->header.source_port = local_addr.port();

    relay_send(local_sockfd, *pack, relay_addr.value());
    delete pack;
  }

  if (local_addr.address().is_v4()) {
    if (!relay_addr.has_value()) {
      logc(LogLevel::Fatal) << "local socket is running on ipv4 but no relay server provided";
      exit(-1);
    }

    is_v4 = true;

    std::thread heartbeat_thread(do_relay_heartbeat);
    heartbeat_thread.detach();
  }

  signal(SIGINT, do_leave);
  signal(SIGKILL, do_leave);
  signal(SIGTERM, do_leave);
  signal(SIGQUIT, do_leave);

  std::thread receive_thread(do_recv);
  receive_thread.detach();

  need_verification = true;
  int64_t retry_time = 100;

  do_verification();

  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(retry_time));

    if (!need_verification) {
      break;
    } else {
      retry_time = std::min(15000L, retry_time * 2L);
    }

    do_verification();
  }

  std::thread routers_update_thread(do_routers_update);
  routers_update_thread.detach();

  std::thread local_api_thread(serve_local_api);
  local_api_thread.detach();

  tun_name[0] = '\0';
  tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
  if (tun_fd < 0) {
    logc(LogLevel::Fatal) << "failed to allocate interface";
    do_leave(-1);
  }

  in6_ifreq ifr6;
  ifr6.ifr6_prefixlen = 64;
  inet_pton(AF_INET6, virtual_ip.to_string().c_str(), &ifr6.ifr6_addr);
  set_host_addr6(tun_name, ifr6);

  logc(LogLevel::Info) << tun_name << " was started on "
                       << virtual_ip.to_string();
  auto rep = virtual_ip.raw_bytes();

  while (true) {
    ra::Packet<OMELET_NL_BUFFER_SIZE> pack;
    nread = read(tun_fd, pack.buf, OMELET_NL_BUFFER_SIZE);

    if (nread < 0) {
      continue;
    }

    pack.header.set(PACKET_FROM_PEERS, PACKET_RAW_IP_PACKET,
                    sizeof pack.header + nread, rep);

    ra::ipv6_address_t raw_addr6;
    std::copy(pack.buf + 24, pack.buf + 40, raw_addr6.begin());

    bool valid = true;

    for (int i = 0; i < 8; ++i) {
      if (raw_addr6[i] != rep[i]) {
        valid = false;
        break;
      }
    }

    if (!valid) {
      continue;
    }

    //    logc(LogLevel::Debug) << "read " << nread << " bytes from " <<
    //    tun_name;

    ra::Address addr6(raw_addr6);
    auto res = routers.query(addr6);

    if (res.has_value()) {
      omelet_send(local_sockfd, pack, res.value());
    }
  }

  return 0;
}