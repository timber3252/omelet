//
// Created by timber3252 on 7/19/19.
//

#include "../base/linux/aes.h"
#include "../base/linux/global.h"
#include "../base/linux/log.h"

uint16_t server_port = 21121, client_listen_port[kMaxConnections];
uint32_t server_sock, client_socks[kMaxConnections], client_ip[kMaxConnections], client_nat_ip[kMaxConnections];
ConsoleLog logc;
char server_ip[kMinBufSize] = "0.0.0.0";

void init() {
  server_sock = socket(PF_INET, SOCK_STREAM, 0);
  if (server_sock == -1) {
    logc(LogLevel::Fatal) << "Failed to create socket object.";
    exit(-1);
  }
  sockaddr_in addr{};
  addr.sin_family = PF_INET;
  addr.sin_port = htons(server_port);
  addr.sin_addr.s_addr = inet_addr(server_ip);
  if (bind(server_sock, (sockaddr *)&addr, sizeof addr) == -1) {
    logc(LogLevel::Fatal) << "Failed to bind ip address.";
    exit(-1);
  }
  if (listen(server_sock, kMaxConnections) == -1) {
    logc(LogLevel::Fatal) << "Failed to listen on " << server_ip << ':'
                          << server_port;
    exit(-1);
  }
  logc(LogLevel::Info) << "Listening on " << server_ip << ':' << server_port;
}

void *serve_thread(void *p) {
  int fd = *static_cast<int *>(p), self = 0;
  sockaddr_in client_sa{};
  socklen_t client_sa_len = sizeof client_sa;
  getpeername(fd, (sockaddr *)&client_sa, &client_sa_len);
  for (int i = 0; i < kMaxConnections; ++i) {
    if (client_socks[i] == fd) {
      self = i;
      break;
    }
  }
  while (true) {
    uint8_t output[kBufSize] = {0}, buf[kBufSize] = {0};
    int len = recv(fd, buf, sizeof buf, 0);
//    logc(LogLevel::Debug) << "recv len: " << len;
    if (len <= 0) {
      int i = 0;
      for (i = 0; i < kMaxConnections; ++i) {
        if (client_socks[i] == fd) {
          client_socks[i] = 0;
          client_ip[i] = 0;
          client_listen_port[i] = 0;
          break;
        }
      }
      logc(LogLevel::Info) << "Client " << fd << "("
                           << inet_ntoa(client_sa.sin_addr) << ':'
                           << ntohs(client_sa.sin_port) << ") has leaved.";
      pthread_exit(nullptr);
    }
    if (aes_decrypt(reinterpret_cast<const unsigned char *>(buf), len, aes_key,
                    output) < 0) {
      logc(LogLevel::Info) << "Packet from client " << fd << "("
                           << inet_ntoa(client_sa.sin_addr) << ':'
                           << ntohs(client_sa.sin_port)
                           << ") could not be decrypted.";
      continue;
    } else {
      switch (output[0]) {
        case PACKET_HEARTBEAT: {
//          logc(LogLevel::Debug) << "Packet decrypted: heartbeat";
          send(fd, buf, len, 0);
          continue;
        }
        case PACKET_QUERY_NAT_SELF: {
          logc(LogLevel::Debug) << "Packet decrypted: query nat self";
          uint8_t reply[kMinBufSize] = {0x00};
          reply[0] = PACKET_QUERY_NAT_SELF;
          reply[1] =
              (*reinterpret_cast<const int *>(&client_sa.sin_addr) & 0xff000000) >> 24;
          reply[2] =
              (*reinterpret_cast<const int *>(&client_sa.sin_addr) & 0x00ff0000) >> 16;
          reply[3] =
              (*reinterpret_cast<const int *>(&client_sa.sin_addr) & 0x0000ff00) >> 8;
          reply[4] =
              *reinterpret_cast<const int *>(&client_sa.sin_addr) & 0x000000ff;
          reply[5] = client_listen_port[self] & 0x00ff;
          reply[6] = (client_listen_port[self] & 0xff00) >> 8;
          reply[7] = 0x00;
          if (aes_encrypt(reinterpret_cast<const unsigned char *>(reply), 8,
                          aes_key, buf) == 0) {
            send(fd, buf, AES_BLOCK_SIZE, 0);
          }
          continue;
        }
        case PACKET_QUERY_CLIENT_LIST: {
          logc(LogLevel::Debug) << "Packet decrypted: query client list";
          uint8_t reply[kBufSize] = {0x00};
          int cnt = 2;
          for (int i = 0; i < kMaxConnections; ++i) {
            if (client_socks[i] > 0) {
              ++reply[1];
              reply[cnt++] = client_ip[i] & 0x000000ff;
              reply[cnt++] = (client_ip[i] & 0x0000ff00) >> 8;
              reply[cnt++] = (client_ip[i] & 0x00ff0000) >> 16;
              reply[cnt++] = (client_ip[i] & 0xff000000) >> 24;
              reply[cnt++] = (client_nat_ip[i] & 0xff000000) >> 24;
              reply[cnt++] = (client_nat_ip[i] & 0x00ff0000) >> 16;
              reply[cnt++] = (client_nat_ip[i] & 0x0000ff00) >> 8;
              reply[cnt++] = client_nat_ip[i] & 0x000000ff;
              while (client_listen_port[i] == 0) {
                sleep(1);
              }
              reply[cnt++] = client_listen_port[i] & 0x00ff;
              reply[cnt++] = (client_listen_port[i] & 0xff00) >> 8;
            }
          }
          reply[0] = PACKET_QUERY_CLIENT_LIST;
          memset(buf, 0x00, sizeof buf);
//          for (int i = 0; i < cnt; ++i) {
//            logc(LogLevel::Debug) << int(reply[i]);
//          }
          if (aes_encrypt(reinterpret_cast<const uint8_t *>(reply), cnt, aes_key, buf) == 0) {
            send(fd, buf,
                 static_cast<size_t>(
                     ceil(cnt / static_cast<double>(AES_BLOCK_SIZE))) *
                 AES_BLOCK_SIZE,
                 0);
          }
          continue;
        }
        case PACKET_REG: {
          client_listen_port[self] = (output[1] | (output[2] << 8));
          if (client_nat_ip[self] == 0x0100007f) { // 127.0.0.1 TODO
            client_nat_ip[self] = (output[3] | (output[4] << 8) | (output[5] << 16) | (output[6] << 24));
          }
          logc(LogLevel::Debug) << "Packet decrypted: reg " << client_listen_port[self] << ' ' << client_nat_ip[self];
          continue;
        }
      }
    }
  }
}

void serve() {
  logc(LogLevel::Info) << "Server has started.";
  const int ip_start = 0x0a010000, ip_end = 0x0ac8ffff;
  union {
    int ip_address_v4_i;
    uint8_t ip_address_v4_s[4];
  } cnt;
  cnt.ip_address_v4_i = ip_start;
  while (true) {
    sockaddr_in client_addr{};
    socklen_t len = sizeof client_addr;
    int fd = accept(server_sock, (sockaddr *)&client_addr, &len);
    if (fd == -1) {
      logc(LogLevel::Error)
          << "Failed to accept client. (errno = " << errno << ")";
      continue;
    }
    int i = 0;
    for (i = 0; i < kMaxConnections; ++i) {
      if (client_socks[i] == 0) {
        uint8_t buf[kMinBufSize];
        client_socks[i] = fd;
        client_ip[i] = ++cnt.ip_address_v4_i;
        client_nat_ip[i] = client_addr.sin_addr.s_addr;
        logc(LogLevel::Debug) << client_ip[i] << ' ' << client_nat_ip[i];
        uint8_t in[kMinBufSize];
        in[0] = PACKET_FIRST_CONFIRM;
        in[1] = cnt.ip_address_v4_s[0];
        in[2] = cnt.ip_address_v4_s[1];
        in[3] = cnt.ip_address_v4_s[2];
        in[4] = cnt.ip_address_v4_s[3];
        logc(LogLevel::Debug) << int(in[4]) << '.' << int(in[3]) << '.' << int(in[2]) << '.' << int(in[1]);
        aes_encrypt(in, 5, aes_key, buf);
        send(fd, buf, AES_BLOCK_SIZE, 0);
        pthread_t tid;
        pthread_create(&tid, nullptr, serve_thread, &fd);
        logc(LogLevel::Info)
            << "Client " << fd << "(" << inet_ntoa(client_addr.sin_addr) << ':'
            << ntohs(client_addr.sin_port) << ") has connected to the server.";
        break;
      }
    }
    if (i == kMaxConnections) {
      const char *str = "Connection rejected: server is full.";
      send(fd, str, strlen(str), 0);
      close(fd);
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc > 1) {
    server_port = atoi(argv[1]);
  }
  init();
  serve();
  return 0;
}