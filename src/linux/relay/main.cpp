//
// Created by timber3252 on 8/1/19.
//

#include "linux/base/global.hpp"

using ra::LogLevel;

ra::ConsoleLog logc;
ra::Endpoint local_addr, server_addr;
ra::RMap<ra::Endpoint, ra::Endpoint> routers_6to4; // 共用 UDP

int local_sockfd;

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

  logc(LogLevel::Info) << "relay server was started on ["
                       << local_addr.address().to_string()
                       << "]:" << local_addr.port();
}

template <size_t size>
void handle_packet(const ra::Endpoint &sender,
                   std::shared_ptr<ra::IPv4RelayPacket<ra::Packet<size>>> pack) {
  uint8_t type = pack->header.packet_type;

  switch(type) {
  case PACKET_RELAY_VERIFICATION: {
    switch(pack->header.packet_source) {
    case PACKET_RELAY_FROM_SERVER: {
      server_addr = sender;
      break;
    }

    case PACKET_RELAY_FROM_IPV4_CLIENT: {
//      routers_6to4.insert(sender, sender);
      break;
    }

    case PACKET_RELAY_FROM_IPV6_CLIENT: {
      ra::ipv6_address_t client_ip;
      std::copy(pack->header.source_ip, pack->header.source_ip + 16, client_ip.begin());
      ra::port_t client_port = pack->header.source_port;
      ra::Endpoint addr(client_ip, client_port);
      routers_6to4.insert(addr, sender);
      break;
    }

    default: {
      break;
    }
    }
    break;
  }

  case PACKET_RELAY_HEARTBEAT: {
    // no need to reply
    break;
  }

  case PACKET_RELAY_RAW_TO_SERVER: {
    pack->header.protocol_id = PROTOCOL_RELAY;

    if (sender.address().is_v6()) {
      logc(LogLevel::Error) << "invalid packet ipv6 -> server through relay server";
      break;
    }

    pack->header.source_port = sender.port();
    auto addr = sender.address().raw_bytes();
    std::copy(addr.begin(), addr.end(), pack->header.source_ip);

    relay_send(local_sockfd, *pack, server_addr);
    break;
  }

  case PACKET_RELAY_RAW_TO_PEERS: {
    ra::ipv6_address_t addr;
    std::copy(pack->header.dest_ip, pack->header.dest_ip + 16, addr.begin());
    ra::Endpoint ep(addr, pack->header.dest_port);

    if (sender.address().is_v4()) {
      if (ep.address().is_v4()) {
        // v4 to v4
        pack->header.source_port = sender.port();
        auto addr1 = sender.address().raw_bytes();
        std::copy(addr1.begin(), addr1.end(), pack->header.source_ip);

        relay_send(local_sockfd, *pack, ep);
      } else {
        // v4 to v6
        auto res = routers_6to4.query(ep);

        if (res.has_value()) {
          pack->header.source_port = sender.port();
          auto addr1 = sender.address().raw_bytes();
          std::copy(addr1.begin(), addr1.end(), pack->header.source_ip);

          relay_send(local_sockfd, *pack, res.value());
        }
      }
    } else {
      if (ep.address().is_v4()) {
        // v6 to v4
        pack->header.source_port = sender.port();
        auto addr1 = sender.address().raw_bytes();
        std::copy(addr1.begin(), addr1.end(), pack->header.source_ip);

        relay_send(local_sockfd, *pack, ep);
      } else {
        // v6 to v6
        logc(LogLevel::Error) << "invalid packet ipv6 -> ipv6 through relay server";
      }
    }
    break;
  }

  default: {
    break;
  }
  }
}

int main(int argc, char *argv[]) {
  int ch;

  local_addr = ra::Endpoint("0.0.0.0:23368");

  while ((ch = getopt(argc, argv, "hl:k:s:b:r:")) != -1) {
    switch (ch) {
    case 'h': {
      printf("Usage: %s arguments                                        \n"
             "  -h           show help                                   \n"
             "  -l addr      set local address (default = 0.0.0.0:23368) \n"
             "  -k aes_key   use specific aes key (length = 128)         \n",
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

    default: {
      break;
    }
    }
  }

  init_socket();

  while (true) {
    std::shared_ptr<ra::IPv4RelayPacket<ra::Packet<OMELET_AL_BUFFER_SIZE>>> pack(
        new ra::IPv4RelayPacket<ra::Packet<OMELET_AL_BUFFER_SIZE>>());
    auto ep = relay_recv(local_sockfd, *pack);

    if (ep.has_value()) {
      std::thread resolve_packet_thread(handle_packet<OMELET_AL_BUFFER_SIZE>, ep.value(), pack);
      resolve_packet_thread.detach();
    }
  }

  return 0;
}