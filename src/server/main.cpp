//
// Created by timber3252 on 7/19/19.
//

#include "../base/linux/aes.h"
#include "../base/linux/global.h"
#include "../base/linux/log.h"
#include "../base/linux/router.h"
#include "../base/linux/thread_safe.h"

ConsoleLog logc;
ipv4_address_t local_address_n;
port_t local_port_n;
sockfd_t sockfd;
Allocator al;
Counter packet_id;
Set reliable_packets;

void omelet_send(int fd, const void *buf, size_t size, int flags,
                 const sockaddr_in *addr, socklen_t addr_len,
                 OmeletProtoHeader &header, bool reliable) {
  if (reliable) {
    logc(LogLevel::Info) << "try to send reliable packet ["
                         << int(header.packet_id) << ", "
                         << int(header.packet_source) << ", "
                         << int(header.packet_type) << ", "
                         << int(header.length) << "] to "
                         << int(header.virtual_ip_n) << " {aka "
                         << inet_ntoa(addr->sin_addr) << ":"
                         << ntohs(addr->sin_port) << "}";
  } else {
    logc(LogLevel::Info) << "sent packet [" << int(header.packet_id) << ", "
                         << int(header.packet_source) << ", "
                         << int(header.packet_type) << ", "
                         << int(header.length) << "] to "
                         << int(header.virtual_ip_n) << " {aka "
                         << inet_ntoa(addr->sin_addr) << ":"
                         << ntohs(addr->sin_port) << "}";
  }
  sendto(fd, buf, size, flags, reinterpret_cast<const sockaddr *>(addr),
         addr_len);
}

void init_socket() {
  sockfd = socket(PF_INET, SOCK_DGRAM, 0);

  if (sockfd < 0) {
    logc(LogLevel::Fatal) << "failed to create socket object (errno = " << errno
                          << ")";
    exit(-1);
  }

  sockaddr_in addr{};
  addr.sin_family = PF_INET;
  addr.sin_port = local_port_n;
  addr.sin_addr.s_addr = local_address_n;

  if (bind(sockfd, (sockaddr *)&addr, sizeof addr) == -1) {
    logc(LogLevel::Fatal) << "failed to bind ip address (errno = " << errno
                          << ")";
    exit(-1);
  }

  logc(LogLevel::Info) << "server was started on " << inet_ntoa(addr.sin_addr)
                       << ':' << ntohs(addr.sin_port);
}

// 提供较为可靠的发包机制，收到对方的确认包后结束，或者超过指定时间后被舍弃
void *reliable_send(void *p) {
  auto arg = (std::pair<Packet<kALBufferSize> *, sockaddr_in> *)p;
  auto *sendout = new uint8_t[kALBufferSize];
  socklen_t addr_len = sizeof(sockaddr_in);

  aes_encrypt(reinterpret_cast<const uint8_t *>(arg->first),
              arg->first->header.length, aes_key, sendout);

  omelet_send(sockfd, sendout,
              (size_t)ceil(arg->first->header.length / (double)kAesBlockSize) *
                  kAesBlockSize,
              0, &(arg->second), addr_len, arg->first->header, true);

  int usecs = 500000;
  for (int i = 0; i < 6; ++i) {
    usleep(usecs);
    usecs = usecs * 2;

    if (!reliable_packets.exist(arg->first->header.packet_id)) {
      if (arg->first->header.packet_type == PACKET_TYPE_VERIFICATION) {
        logc(LogLevel::Info) << "client " << arg->first->header.virtual_ip_n
                             << " {aka " << inet_ntoa(arg->second.sin_addr)
                             << ":" << ntohs(arg->second.sin_port) << "}"
                             << " has connected to the server";
      }
      auto header = arg->first->header;
      logc(LogLevel::Info) << "sent reliable packet [" << int(header.packet_id)
                           << ", " << int(header.packet_source) << ", "
                           << int(header.packet_type) << ", "
                           << int(header.length) << "] to "
                           << int(header.virtual_ip_n) << " {aka "
                           << inet_ntoa(arg->second.sin_addr) << ":"
                           << ntohs(arg->second.sin_port) << "}";
      break;
    }

    omelet_send(
        sockfd, sendout,
        (size_t)ceil(arg->first->header.length / (double)kAesBlockSize) *
            kAesBlockSize,
        0, &(arg->second), addr_len, arg->first->header, true);
  }

  reliable_packets.remove(arg->first->header.packet_id);
  delete[] sendout;
  delete arg->first;
  delete arg;
  pthread_exit(nullptr);
}

// 对获取到的数据包进行解析
void *resolve_packet(void *p) {
  auto arg = (std::pair<Packet<kALBufferSize> *, sockaddr_in> *)p;
  uint8_t type = arg->first->header.packet_type;
  socklen_t addr_len = sizeof(sockaddr_in);
  auto *sendout = new uint8_t[kALBufferSize];

  if ((type & PACKET_NEED_REPLY) > 0) {
    type &= PACKET_UNIQUE_OPERATION;

    switch (type) {
      // 对于心跳包回复 ACK，同时起着保持 NAT 不变的作用
      case PACKET_TYPE_HEARTBEAT: {
        arg->first->header.set(packet_id.add(), PACKET_SERVER,
                               PACKET_TYPE_HEARTBEAT | PACKET_NO_REPLY,
                               sizeof(arg->first->header), 0);

        aes_encrypt(reinterpret_cast<const uint8_t *>(arg->first),
                    arg->first->header.length, aes_key, sendout);
        omelet_send(sockfd, sendout, kAesBlockSize, 0, &(arg->second), addr_len,
                    arg->first->header, false);
        delete arg->first;
        delete arg;
        delete[] sendout;
        break;
      }

      // 获取客户端路由表操作，需要注意阻塞问题和多次发包问题（因为数据量相对较大
      case PACKET_TYPE_GET_ROUTERS: {
        int ncnt = al.query_all(arg->first->data,
                                kALBufferSize - sizeof(arg->first->header));
        arg->first->header.set(packet_id.add(), PACKET_SERVER,
                               PACKET_TYPE_GET_ROUTERS | PACKET_NEED_REPLY,
                               sizeof(arg->first->header) + ncnt, 0);

        reliable_packets.insert(
            arg->first->header
                .packet_id);  // 意味着客户端相同意义的申请只能发一次
        pthread_t tid;
        pthread_create(&tid, nullptr, reliable_send, arg);
        break;
      }

      // 是客户端发给服务器的第一个包，返回其 NAT 地址用于配置本机 TUN 设备
      case PACKET_TYPE_VERIFICATION: {
        union {
          ipv4_address_t i;
          uint8_t s[4];
        } virtual_ip_n;

        virtual_ip_n.i = arg->first->header.virtual_ip_n;

        memcpy(arg->first->data, virtual_ip_n.s, sizeof virtual_ip_n.s);

        arg->first->header.set(packet_id.add(), PACKET_SERVER,
                               PACKET_TYPE_VERIFICATION | PACKET_NEED_REPLY,
                               sizeof(arg->first->header) + 4, virtual_ip_n.i);
        reliable_packets.insert(arg->first->header.packet_id);
        pthread_t tid;
        pthread_create(&tid, nullptr, reliable_send, arg);
        break;
      }
    }
  } else if ((type & PACKET_NO_REPLY) > 0) {
    type &= PACKET_UNIQUE_OPERATION;

    switch (type) {
      // 客户端主动退出服务器，是显式的退出，但并非严格（部分客户端可能已经无效，但仍然不认为是退出了服务器）
      case PACKET_TYPE_LEAVE: {
        al.remove(arg->first->header.virtual_ip_n);
        logc(LogLevel::Info) << "client " << arg->first->header.virtual_ip_n
                             << " {aka " << inet_ntoa(arg->second.sin_addr)
                             << ":" << ntohs(arg->second.sin_port) << "}"
                             << " was explicitly leaved";
        delete arg->first;
        delete arg;
        delete[] sendout;
        break;
      }

      case PACKET_TYPE_HANDSHAKE_REQUEST: {
        // 保证握手请求效率，不进行可靠发包，而是每次客户端向服务端发三个相同 ID
        // 的包，服务端每收到一个握手请求，就向目标客户端发送请求，在丢包率较为合理的情况下能够保证正常

        union {
          ipv4_address_t i;
          uint8_t s[4];
        } dest_ip_n;
        memcpy(dest_ip_n.s, arg->first->data, 4);  // 第一次请求为虚拟 IP

        Peer source_peer = al.query(arg->first->header.virtual_ip_n);
        Peer dest_peer = al.query(dest_ip_n.i);

        if (dest_peer.ip_n == 0 || dest_peer.port_n == 0) break;

        arg->first->header.set(packet_id.add(), PACKET_SERVER,
                               PACKET_TYPE_HANDSHAKE_REQUEST | PACKET_NO_REPLY,
                               sizeof(arg->first->header) + sizeof(Peer), 0);

        sockaddr_in peer_addr{};
        peer_addr.sin_family = PF_INET;
        peer_addr.sin_port = dest_peer.port_n;
        peer_addr.sin_addr.s_addr = dest_peer.ip_n;

        memcpy(arg->first->data, &source_peer, sizeof source_peer);

        aes_encrypt(reinterpret_cast<const uint8_t *>(arg->first),
                    arg->first->header.length, aes_key, sendout);
        omelet_send(
            sockfd, sendout,
            (size_t)ceil(arg->first->header.length / (double)kAesBlockSize) *
                kAesBlockSize,
            0, &(peer_addr), sizeof peer_addr, arg->first->header, false);

        delete arg->first;
        delete arg;
        delete[] sendout;
        break;
      }

      // 与可靠发包机制对应
      case PACKET_TYPE_GET_ROUTERS: {
        reliable_packets.remove(arg->first->header.packet_id);
        delete arg->first;
        delete arg;
        delete[] sendout;
        break;
      }

      case PACKET_TYPE_VERIFICATION: {
        reliable_packets.remove(arg->first->header.packet_id);
        delete arg->first;
        delete arg;
        delete[] sendout;
        break;
      }
    }
  }
  pthread_exit(nullptr);
}

int main(int argc, char *argv[]) {
  int ch;
  local_port_n = 33106, local_address_n = 0;

  while ((ch = getopt(argc, argv, "hl:k:")) != -1) {
    switch (ch) {
      case 'h': {
        printf(
            "Usage: %s arguments ..                                        \n"
            "  -h              show help                                   \n"
            "  -l address      set local address (default = 0.0.0.0:21121) \n"
            "  -k aes_key      use specific aes key (length = 128)         \n",
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
    }
  }

  init_socket();

  uint8_t buf[kALBufferSize], dbuf[kALBufferSize];
  sockaddr_in client_addr{};
  socklen_t client_addr_len = sizeof(sockaddr_in);
  ipv4_address_t begin_h = 0x0a010000, end_h = 0x0ac8ffff, now_h = begin_h;

  while (true) {
    int nrecv = recvfrom(sockfd, buf, kALBufferSize, 0,
                         (sockaddr *)&client_addr, &client_addr_len);
    if (nrecv < 0) {
      continue;
    }

    if (aes_decrypt(buf, nrecv, aes_key, dbuf) < 0) {
      continue;
    }

    auto *arg = new std::pair<Packet<kALBufferSize> *, sockaddr_in>();

    arg->first = new Packet<kALBufferSize>();
    memcpy(&(arg->first->header), dbuf, sizeof(arg->first->header));

    // 数据包对象必须是服务器，否则舍弃
    if (arg->first->header.packet_source != PACKET_SERVER) {
      continue;
    }

    // 第一次发包，但服务器已满
    if (!al.exist(arg->first->header.virtual_ip_n) &&
        al.size() > kMaxConnections) {
      // TODO: 返回包
      continue;
    }

    // 分配新的虚拟 IP 地址，注意统一使用网络字节序
    if (!al.exist(arg->first->header.virtual_ip_n)) {
      arg->first->header.virtual_ip_n = htonl(++now_h);

      al.insert(arg->first->header.virtual_ip_n,
                Peer(client_addr.sin_addr.s_addr, client_addr.sin_port));

      logc(LogLevel::Info) << "try binding " << arg->first->header.virtual_ip_n
                           << " to " << inet_ntoa(client_addr.sin_addr) << ":"
                           << ntohs(client_addr.sin_port);
    }

    auto header = arg->first->header;
    auto res = al.query(arg->first->header.virtual_ip_n);
    if (res.ip_n != arg->second.sin_addr.s_addr ||
        res.port_n != arg->second.sin_port) {
      al.remove(res.ip_n);
      al.insert(arg->first->header.virtual_ip_n,
                Peer(client_addr.sin_addr.s_addr, client_addr.sin_port));
    }

    logc(LogLevel::Info) << "received packet [" << int(header.packet_id) << ", "
                         << int(header.packet_source) << ", "
                         << int(header.packet_type) << ", "
                         << int(header.length) << "] from "
                         << arg->first->header.virtual_ip_n << " {aka "
                         << inet_ntoa(client_addr.sin_addr) << ":"
                         << ntohs(client_addr.sin_port) << "}";

    memcpy(arg->first->data, dbuf + sizeof(arg->first->header),
           arg->first->header.length - sizeof(arg->first->header));

    arg->second = client_addr;

    // 保证该过程不阻塞
    pthread_t tid;
    pthread_create(&tid, nullptr, resolve_packet, (void *)arg);

    memset(buf, 0x00, sizeof buf);
  }
  return 0;
}