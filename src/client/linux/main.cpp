//
// Created by timber3252 on 7/19/19.
//

#include "../../base/linux/global.h"
#include "../../base/linux/log.h"
#include "../../base/linux/aes.h"
#include "../../base/linux/router.h"

char server_ip[kMinBufSize] = "127.0.0.1", client_listen_ip[kMinBufSize] = "0.0.0.0";
uint16_t server_port = 21121, client_listen_port = 36868;
uint32_t client_sock, client_listen_sock, peer_socks[kMaxConnections], self_virtual_ip;
ConsoleLog logc;
int tun_fd, nread;
char tun_name[IFNAMSIZ];

Router router;
std::mutex mtx;

struct Packet {
  uint8_t *encrypted_data;
  uint32_t length;
  union {
    uint32_t ipv4_address_i;
    uint8_t ipv4_address_s[4];
  } dest_ip;
};

int tun_alloc(char *dev, int flags) {
  assert(dev != nullptr);
  ifreq ifr {};
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

int set_host_addr(const char* dev, int virtual_ip) {

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
  if (ioctl(sockfd, SIOCSIFADDR, (void *) &ifr) < 0) {
    perror("ioctl SIOCSIFADDR");
    return -2;
  }
  if (ioctl(sockfd, SIOCGIFFLAGS, (void *) &ifr) < 0) {
    perror("ioctl SIOCGIFFLAGS");
    return -3;
  }
  ifr.ifr_flags |= IFF_UP;
  if (ioctl(sockfd, SIOCSIFFLAGS, (void *) &ifr) < 0) {
    perror("ioctl SIOCSIFFLAGS");
    return -4;
  }
  inet_pton(AF_INET, "255.0.0.0", &addr.sin_addr);
  bcopy(&addr, &ifr.ifr_netmask, sizeof addr);
  if (ioctl(sockfd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
    perror("ioctl SIOCSIFNETMASK");
    return -5;
  }

  close(sockfd);
  return 0;
}

void init() {
  client_sock = socket(PF_INET, SOCK_STREAM, 0);
  sockaddr_in addr {};
  addr.sin_family = PF_INET;
  addr.sin_port = htons(server_port);
  addr.sin_addr.s_addr = inet_addr(server_ip);

  if (connect(client_sock, (sockaddr *)&addr, sizeof addr) == -1) {
    logc(LogLevel::Fatal) << "Failed to connect the server.";
    exit(-1);
  }

  logc(LogLevel::Info) << "Successfully connected to the server.";
  client_listen_sock = socket(PF_INET, SOCK_STREAM, 0);

  if (client_listen_sock == -1) {
    logc(LogLevel::Fatal) << "Failed to create listen socket object.";
    exit(-1);
  }

  sockaddr_in client_listen_addr {};
  client_listen_addr.sin_family = PF_INET;
  client_listen_addr.sin_port = htons(client_listen_port);
  client_listen_addr.sin_addr.s_addr = inet_addr(client_listen_ip);

  if (bind(client_listen_sock, (sockaddr *)&client_listen_addr, sizeof client_listen_addr) == -1) {
    logc(LogLevel::Fatal) << "Failed to bind ip address.";
    exit(-1);
  }

  if (listen(client_listen_sock, kMaxConnections) == -1) {
    logc(LogLevel::Fatal) << "Failed to listen on " << client_listen_ip << ':'
                          << client_listen_port;
    exit(-1);
  }

  uint8_t tmpbuf[kMinBufSize], tmppacket[kMinBufSize];
  tmpbuf[0] = PACKET_REG;
  tmpbuf[1] = client_listen_port & 0x00ff;
  tmpbuf[2] = (client_listen_port & 0xff00) >> 8;
  int ipi = inet_addr(client_listen_ip);
  tmpbuf[3] = (ipi & 0x000000ff);
  tmpbuf[4] = (ipi & 0x0000ff00) >> 8;
  tmpbuf[5] = (ipi & 0x00ff0000) >> 16;
  tmpbuf[6] = (ipi & 0xff000000) >> 24;
  aes_encrypt(tmpbuf, 7, aes_key, tmppacket);
  send(client_sock, tmppacket, AES_BLOCK_SIZE, 0);
}

void* heartbeat_thread(void *) {
  const uint8_t str[2] = { PACKET_HEARTBEAT, 0x00 };
  uint8_t packet[AES_BLOCK_SIZE];
  aes_encrypt(str, 0x01, aes_key, packet);

  while (true) {
    if (send(client_sock, packet, AES_BLOCK_SIZE, 0) < 0) {
      pthread_exit(nullptr);
    }

    sleep(10);
  }
}

void* serve_thread(void *p) {
  int fd = *static_cast<int *>(p), self;
  sockaddr_in peer_sa{};
  socklen_t peer_sa_len = sizeof peer_sa;
  getpeername(fd, (sockaddr *)&peer_sa, &peer_sa_len);

  for (int i = 0; i < kMaxConnections; ++i) {
    if (peer_socks[i] == fd) {
      self = i;
      break;
    }
  }

  while (true) {
    uint8_t output[kProtocolMaxSize] = {0}, buf[kProtocolMaxSize] = {0};
    int len = recv(fd, buf, sizeof buf, 0);
    if (len <= 0) {
      int i = 0;

      for (i = 0; i < kMaxConnections; ++i) {
        if (peer_socks[i] == fd) {
          peer_socks[i] = 0;
          break;
        }
      }

      logc(LogLevel::Info) << "Peer " << fd << "("
                           << inet_ntoa(peer_sa.sin_addr) << ':'
                           << ntohs(peer_sa.sin_port) << ") has disconnected.";
      pthread_exit(nullptr);
    }

    if (aes_decrypt(reinterpret_cast<const unsigned char *>(buf), len, aes_key,
                    output) < 0) {
      logc(LogLevel::Info) << "Packet from client " << fd << "("
                           << inet_ntoa(peer_sa.sin_addr) << ':'
                           << ntohs(peer_sa.sin_port)
                           << ") could not be decrypted.";
      close(fd);
      continue;
    }

    int nwrite = write(tun_fd, &output[2], (output[0] | (output[1]) << 8));

    for (int i = 0; i < nwrite; ++i) {
      printf("%d ", (int)output[2 + i]);
    }
    printf("\n");

    logc(LogLevel::Debug) << "Write " << nwrite << " bytes to tun device.";
  }
}

void* recv_from_server(void *) {
  while (true) {
    uint8_t result[kBufSize] = {0}, buf[kBufSize] = {0};
    int nrecv = recv(client_sock, buf, sizeof buf, 0);

    if (nrecv <= 0) {
      client_sock = socket(PF_INET, SOCK_STREAM, 0);
      sockaddr_in addr {};
      addr.sin_family = PF_INET;
      addr.sin_port = htons(server_port);
      addr.sin_addr.s_addr = inet_addr(server_ip);

      if (connect(client_sock, (sockaddr *)&addr, sizeof addr) == -1) {
        logc(LogLevel::Fatal) << "Failed to reconnect the server.";
        exit(-1);
      }

      logc(LogLevel::Info) << "Successfully reconnected to the server.";
      pthread_t tid_1;
      pthread_create(&tid_1, nullptr, heartbeat_thread, nullptr);
      continue;
    } else {
      if (aes_decrypt(buf, nrecv, aes_key, result) < 0) {
        logc(LogLevel::Info) << "Failed to decrypted package";
      }

      switch(result[0]) {
        case PACKET_HEARTBEAT: {
//          logc(LogLevel::Debug) << "Packet decrypted: heartbeat response";
          continue;
        }

        case PACKET_FIRST_CONFIRM: {
          logc(LogLevel::Debug) << "Packet decrypted: first confirm";
          union {
            uint32_t ipv4_address_i;
            uint8_t ipv4_address_s[4];
          } self_ip;

          self_ip.ipv4_address_s[3] = result[1];
          self_ip.ipv4_address_s[2] = result[2];
          self_ip.ipv4_address_s[1] = result[3];
          self_ip.ipv4_address_s[0] = result[4];
          self_virtual_ip = self_ip.ipv4_address_i;

          logc(LogLevel::Info) << "Allocated IP: " << int(self_ip.ipv4_address_s[0]) << '.'
                               << int(self_ip.ipv4_address_s[1]) << '.' << int(self_ip.ipv4_address_s[2]) << '.'
                               << int(self_ip.ipv4_address_s[3]) << "(" << self_ip.ipv4_address_i << ")";

          int ret = set_host_addr(tun_name, self_ip.ipv4_address_i);

          if (ret < 0) {
            logc(LogLevel::Fatal) << "Failed to set address of tun device. (errcode = " << ret << ")";
            exit(-1);
          }

          continue;
        }

        case PACKET_QUERY_NAT_SELF: {
          // TODO
          continue;
        }

        case PACKET_QUERY_CLIENT_LIST: {
          logc(LogLevel::Debug) << "Packet decrypted: query client list response";
          int ncnt = result[1], cnt = 2;
          uint16_t port;
          union {
            uint32_t ipv4_address_i;
            uint8_t ipv4_address_s[4];
          } virtual_ip, nat_ip;
          do {
            virtual_ip.ipv4_address_s[0] = result[cnt++];
            virtual_ip.ipv4_address_s[1] = result[cnt++];
            virtual_ip.ipv4_address_s[2] = result[cnt++];
            virtual_ip.ipv4_address_s[3] = result[cnt++];
            nat_ip.ipv4_address_s[0] = result[cnt++];
            nat_ip.ipv4_address_s[1] = result[cnt++];
            nat_ip.ipv4_address_s[2] = result[cnt++];
            nat_ip.ipv4_address_s[3] = result[cnt++];
            port = result[cnt++];
            port |= (result[cnt++] << 8);
            logc(LogLevel::Info) << virtual_ip.ipv4_address_i << ' ' << nat_ip.ipv4_address_i << ' ' << port;
            router.insert(virtual_ip.ipv4_address_i, nat_ip.ipv4_address_i, port);
          } while (--ncnt > 0);
          continue;
        }
      }
    }
  }
}

void* wait_thread(void *) {
  logc(LogLevel::Info) << "Listening on " << client_listen_ip << ':' << client_listen_port;

  while (true) {
    sockaddr_in peer {};
    socklen_t peer_len = sizeof peer;
    int fd = accept(client_listen_sock, (sockaddr *)&peer, &peer_len);

    if (fd == -1) {
      logc(LogLevel::Error)
          << "Failed to accept client. (errno = " << errno << ")";
      continue;
    }

    int i = 0;

    for (i = 0; i < kMaxConnections; ++i) {
      if (peer_socks[i] == 0) {
        peer_socks[i] = fd;
        logc(LogLevel::Info)
            << "Peer " << fd << "(" << inet_ntoa(peer.sin_addr) << ':'
            << ntohs(peer.sin_port) << ") has connected to this client.";
        pthread_t tid;
        pthread_create(&tid, nullptr, serve_thread, &fd);
        break;
      }
    }

    if (i == kMaxConnections) {
      const char *str = "Connection rejected: peers are overlimited.";
      send(fd, str, strlen(str), 0);
      close(fd);
    }
  }
}

void* async_wait_and_forward(void *p) {
  auto *data = (Packet*)p;
  int time_usec = 0;
  for (int i = 0; i < 22; ++i) {
    Router::RouterNode *res = router.query(data->dest_ip.ipv4_address_i);
    if (res == nullptr) {
      usleep(time_usec);
      if (time_usec == 0) {
        time_usec = 1;
      } else {
        time_usec = time_usec * 2;
      }
    } else {
      if (res->sockfd == 0 || send(res->sockfd, data->encrypted_data, data->length, 0) < 0) {
        int sockfd = socket(PF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
          // TODO
          continue;
        }
        sockaddr_in addr;
        addr.sin_family = PF_INET;
        addr.sin_port = htons(res->port);
        addr.sin_addr.s_addr = htonl(res->ip);
        if (connect(sockfd, (sockaddr *)&addr, sizeof(addr)) == -1){
          logc(LogLevel::Error) << "Failed to forward message to the peer (" << res->ip
                                << ':' << res->port << ").";
          continue;
        }
        if (res->sockfd)
          close(res->sockfd);
        router.modify(data->dest_ip.ipv4_address_i, sockfd);
        send(sockfd, data->encrypted_data, data->length, 0);
      }
      pthread_exit(nullptr);
    }
  }
  pthread_exit(nullptr);
}

int main(int argc, char *argv[]) {
  int ch;

  while ((ch = getopt(argc, argv, "a:b:hp:q:")) != -1) {

    switch(ch) {
      case 'a': {
        strcpy(server_ip, optarg);
        break;
      }

      case 'b': {
        strcpy(client_listen_ip, optarg);
        break;
      }

      case 'p': {
        server_port = atoi(optarg);
        break;
      }

      case 'q': {
        client_listen_port = atoi(optarg);
        break;
      }

      case 'h': {
        printf("Usage: %s arguments ..                           \n"
               "  -a address     set server ip address (v4 only) \n"
               "  -b address     set client listen ip            \n"
               "  -h             show help                       \n"
               "  -p port        set server port                 \n"
               "  -q port        set client listen port          \n"
               , argv[0]);
        return 0;
      }
    }
  }

  uint8_t buffer[kProtocolMaxSize], req_query_client_list[kMinBufSize], output[kMinBufSize];
  tun_name[0] = '\0';
  tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
  if (tun_fd < 0) {
    logc(LogLevel::Fatal) << "Failed to allocate interface.";
    exit(-1);
  }

  logc(LogLevel::Info) << "Open tun device: " << tun_name << " for reading ...";

  init();
  pthread_t tid_1, tid_2, tid_3;
  pthread_create(&tid_1, nullptr, heartbeat_thread, nullptr);
  pthread_create(&tid_2, nullptr, wait_thread, nullptr);
  pthread_create(&tid_3, nullptr, recv_from_server, nullptr);

  union {
    uint8_t ipv4_address_s[4];
    uint32_t ipv4_address_i;
  } source_ip, dest_ip;

  req_query_client_list[0] = PACKET_QUERY_CLIENT_LIST;
  aes_encrypt(req_query_client_list, kMinBufSize, aes_key, output);
  std::swap(output, req_query_client_list);

  while (true) {
    nread = read(tun_fd, &buffer[2], (sizeof buffer) - 2);

    if (nread < 0) {
      logc(LogLevel::Error) << "Failed to read from interface.";
      close(tun_fd);
      exit(-1);
    }

    buffer[0] = nread & 0x00ff;
    buffer[1] = (nread & 0xff00) >> 8;

    source_ip.ipv4_address_s[3] = buffer[14];
    source_ip.ipv4_address_s[2] = buffer[15];
    source_ip.ipv4_address_s[1] = buffer[16];
    source_ip.ipv4_address_s[0] = buffer[17];
    dest_ip.ipv4_address_s[3] = buffer[18];
    dest_ip.ipv4_address_s[2] = buffer[19];
    dest_ip.ipv4_address_s[1] = buffer[20];
    dest_ip.ipv4_address_s[0] = buffer[21];

    if (dest_ip.ipv4_address_s[3] != 10) {
      continue;
    }

    logc(LogLevel::Debug) << (int)dest_ip.ipv4_address_s[3] << '.' << (int)dest_ip.ipv4_address_s[2] << '.' << (int)dest_ip.ipv4_address_s[1] << '.' << (int)dest_ip.ipv4_address_s[0] << ' ' << dest_ip.ipv4_address_i;
    logc(LogLevel::Debug) << "Read " << nread << " bytes from tun device.";

    for (int i = 0; i < nread; ++i) {
      printf("%d ", (int)buffer[2 + i]);
    }
    printf("\n");

    Router::RouterNode *res = router.query(dest_ip.ipv4_address_i);

    if (res == nullptr) {
      Packet *data = new Packet();
      data->encrypted_data = new uint8_t[kProtocolMaxSize];
      data->dest_ip.ipv4_address_i = dest_ip.ipv4_address_i;
      aes_encrypt(buffer, nread + 2, aes_key, data->encrypted_data);
      data->length = (size_t)ceil((nread + 2) / (double)AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
      send(client_sock, req_query_client_list, AES_BLOCK_SIZE, 0);

      pthread_t wait_tid;
      pthread_create(&wait_tid, nullptr, async_wait_and_forward, data);
      continue;
    } else {
      uint8_t encrypted_data[kProtocolMaxSize];
      aes_encrypt(buffer, nread + 2, aes_key, encrypted_data);

      if (res->sockfd == 0 || send(res->sockfd, encrypted_data, (size_t)ceil((nread + 2) / (double)AES_BLOCK_SIZE) * AES_BLOCK_SIZE, 0) < 0) {
        int sockfd = socket(PF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
          // TODO
          continue;
        }
        sockaddr_in addr;
        addr.sin_family = PF_INET;
        addr.sin_port = htons(res->port);
        addr.sin_addr.s_addr = htonl(res->ip);
        if (connect(sockfd, (sockaddr *)&addr, sizeof(addr)) == -1){
          logc(LogLevel::Error) << "Failed to forward message to the peer (" << res->ip
                                << ':' << res->port << ").";
          continue;
        }
        if (res->sockfd)
          close(res->sockfd);
        router.modify(dest_ip.ipv4_address_i, sockfd);
        send(sockfd, encrypted_data, (size_t)ceil((nread + 2) / (double)AES_BLOCK_SIZE) * AES_BLOCK_SIZE, 0);
      }
    }
  }
  return 0;
}
