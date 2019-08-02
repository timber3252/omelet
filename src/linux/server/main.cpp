//
// Created by timber3252 on 7/28/19.
//

#include "linux/base/global.hpp"

// TODO: 服务器需要严格支持 IPv6？
// TODO: 可以使用 IPv4 中转服务器处理

using ra::LogLevel;

ra::ConsoleLog logc;
ra::Endpoint local_addr;
ra::RMap<ra::Address, ra::Endpoint> routers;
ra::Address allocator;

int local_sockfd;

template <size_t size>
void omelet_send(int fd, const ra::Packet<size> &pack, ra::Endpoint ep) {
  auto *enc_pack = new uint8_t[size];
  int len = ra::aes_encrypt(pack.const_data(), pack.header.length, ra::aes_key,
                            enc_pack);

  //  logc(LogLevel::Info) << "send packet [" << int(pack.header.packet_source)
  //  << ", " << int(pack.header.packet_type) << ", " << pack.header.length <<
  //  "]";

  // TODO: ErrorEvent Queue
  sendto(fd, enc_pack, len, 0,
         reinterpret_cast<const sockaddr *>(&ep.raw_sockaddr()),
         sizeof ep.raw_sockaddr());

  delete[] enc_pack;
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

  //  logc(LogLevel::Info) << "receive packet [" <<
  //  int(pack.header.packet_source) << ", " << int(pack.header.packet_type) <<
  //  ", " << pack.header.length << "]";

  return ra::Endpoint(sender_addr);
}

void do_close(int sig) {
  ra::Packet<OMELET_CMD_BUFFER_SIZE> pack;
  pack.header.set(PACKET_FROM_SERVER, PACKET_SERVER_CLOSED, sizeof pack.header);

  routers.query_all([&](const ra::Address &first, const ra::Endpoint &second) {
    omelet_send(local_sockfd, pack, second);
  });

  exit(sig);
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
    logc(LogLevel::Fatal) << "failed to bind ip address";
    logc(LogLevel::Fatal) << "last error code: " << errno;
    exit(-1);
  }

  logc(LogLevel::Info) << "server was started on ["
                       << local_addr.address().to_string()
                       << "]:" << local_addr.port();
}

template <size_t size>
void handle_packet(const ra::Endpoint &sender,
                   std::shared_ptr<ra::Packet<size>> pack) {
  uint8_t type = pack->header.packet_type;

  switch (type) {
  case PACKET_GET_ROUTERS: {
    auto *reply = new ra::Packet<OMELET_AL_BUFFER_SIZE>();

    reply->header.set(PACKET_FROM_SERVER, PACKET_GET_ROUTERS,
                      sizeof reply->header);

    routers.query_all<ra::Packet<size>>(*reply, [](const ra::Address &first,
                                                   const ra::Endpoint &second,
                                                   ra::Packet<size> &packet) {
      auto addr_1 = first.raw_bytes(), addr_2 = second.address().raw_bytes();

      std::copy(addr_1.begin(), addr_1.end(),
                packet.data() + packet.header.length);
      packet.header.length += addr_1.size();

      std::copy(addr_2.begin(), addr_2.end(),
                packet.data() + packet.header.length);
      packet.header.length += addr_2.size();

      packet.data()[packet.header.length++] = second.port() & 0x00ffu;
      packet.data()[packet.header.length++] = (second.port() & 0xff00u) >> 8u;

      //      logc(LogLevel::Debug) << first.to_string() << " -> " <<
      //      second.address().to_string();
    });

    omelet_send(local_sockfd, *reply, sender);
    delete reply;
    break;
  }

  case PACKET_VERIFICATION: {
    auto *reply = new ra::Packet<OMELET_CMD_BUFFER_SIZE>();

    if (routers.size() > kMaxConnections) {
      reply->header.set(PACKET_FROM_SERVER, PACKET_ERROR_SERVER_FULL,
                        sizeof reply->header);
      omelet_send(local_sockfd, *reply, sender);
    } else {
      auto current_virtual_ip = ++allocator;

      if (pack->header.length == sizeof pack->header) {
        // IPv6 or Fallback IPv4
        routers.insert(current_virtual_ip, sender);

        logc(LogLevel::Debug) << current_virtual_ip.to_string() << " A";
      } else {
        // IPv6
        ra::ipv6_address_t sender_ip;
        std::copy(pack->buf, pack->buf + 16, sender_ip.begin());
        ra::Endpoint sender_ep(sender_ip, sender.port());

        routers.insert(current_virtual_ip, sender_ep);

        logc(LogLevel::Debug) << current_virtual_ip.to_string() << " B";
      }

      reply->header.set(PACKET_FROM_SERVER, PACKET_VERIFICATION,
                        sizeof reply->header);
      std::copy(current_virtual_ip.raw_bytes().begin(),
                current_virtual_ip.raw_bytes().end(), reply->buf);

      reply->header.length += current_virtual_ip.raw_bytes().size();
      omelet_send(local_sockfd, *reply, sender);
    }

    delete reply;
    break;
  }

  case PACKET_LEAVE: {
    ra::ipv6_address_t sender_virtual_ip;
    std::copy(pack->header.virtual_ip_n, pack->header.virtual_ip_n + 16,
              sender_virtual_ip.begin());

    ra::Address sender_virtual_addr(sender_virtual_ip);

    if (routers.exist(sender_virtual_addr)) {
      routers.remove(sender_virtual_addr);
      logc(LogLevel::Info) << "client " << sender_virtual_addr.to_string()
                           << " has leaved";
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

  local_addr = ra::Endpoint("[::]:21121");
  allocator.random();

  while ((ch = getopt(argc, argv, "hl:k:r:")) != -1) {
    switch (ch) {
    case 'h': {
      printf("Usage: %s arguments (IPv6 Only)                               \n"
             "  -h              show help                                   \n"
             "  -l addr         set local address (default = [::]:21121)    \n"
             "  -k aes_key      use specific aes key (length = 128)         \n"
             "  -r addr         use relay server (optional)                 \n",
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

    case 'r': {
      // TODO: RELAY SERVER

      break;
    }

    default: {
      break;
    }
    }
  }

  if (local_addr.address().is_v4()) {
    logc(LogLevel::Fatal) << "invalid ipv6 support";
  }

  init_socket();

  signal(SIGINT, do_close);
  signal(SIGKILL, do_close);
  signal(SIGTERM, do_close);
  signal(SIGQUIT, do_close);

  while (true) {
    std::shared_ptr<ra::Packet<OMELET_AL_BUFFER_SIZE>> pack(
        new ra::Packet<OMELET_AL_BUFFER_SIZE>);
    auto sender = omelet_recv(local_sockfd, *pack);

    if (sender.has_value()) {
      if (pack->header.packet_source != PACKET_FROM_CLIENT) {
        continue;
      }

      std::thread resolve_thread(handle_packet<OMELET_AL_BUFFER_SIZE>,
                                 sender.value(), pack);
      resolve_thread.detach();
    }
  }

  return 0;
}