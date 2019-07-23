//
// Created by timber3252 on 7/20/19.
//

#ifndef OMELET_ROUTER_H
#define OMELET_ROUTER_H

#include "global.h"
#include "thread_safe.h"

class Router {
 public:
  struct RouterNode {
    RouterNode() : ip(0), port(0) { ch[0] = ch[1] = 0; }

    RouterNode *ch[2];
    uint32_t ip;
    uint16_t port;
  };

  Router() { rt = new RouterNode(); }
  ~Router() { clean(rt); }

  void clean(RouterNode *now) {
    for (int i = 0; i < 2; ++i) {
      if (now->ch[i] != nullptr) {
        clean(now->ch[i]);
      }
    }
    delete now;
  }

  void insert(uint32_t key, uint32_t ip, uint16_t port) {
    mtx.lock();
    RouterNode *now = rt;
    for (int i = 0; i < 32; ++i, key >>= 1) {
      int nxt = key & 1;
      if (now->ch[nxt] == nullptr) now->ch[nxt] = new RouterNode();
      now = now->ch[nxt];
    }
    now->ip = ip, now->port = port;
    mtx.unlock();
  }

  RouterNode *query(uint32_t key) {
    RouterNode *now = rt;
    for (int i = 0; i < 32; ++i, key >>= 1) {
      int nxt = key & 1;
      if (now->ch[nxt] == nullptr) return nullptr;
      now = now->ch[nxt];
    }
    return now;
  }

  void update_all(uint8_t *buf, uint16_t len, Set &s) {
    if (len % 10 != 0) {
      return;
    }

    int ncnt = len / 10, cnt = 0;
    union {
      ipv4_address_t i;
      uint8_t s[4];
    } virtual_ip_n, dest_ip_n;
    port_t dest_port_n;

    for (int i = 0; i < ncnt; ++i) {
      virtual_ip_n.s[0] = buf[cnt++];
      virtual_ip_n.s[1] = buf[cnt++];
      virtual_ip_n.s[2] = buf[cnt++];
      virtual_ip_n.s[3] = buf[cnt++];

      dest_ip_n.s[0] = buf[cnt++];
      dest_ip_n.s[1] = buf[cnt++];
      dest_ip_n.s[2] = buf[cnt++];
      dest_ip_n.s[3] = buf[cnt++];

      dest_port_n = buf[cnt++];
      dest_port_n |= (buf[cnt++] << 8);

      s.insert(virtual_ip_n.i);
      this->insert(virtual_ip_n.i, dest_ip_n.i, dest_port_n);
    }
  }

 private:
  std::mutex mtx;
  RouterNode *rt;
};

#endif  // OMELET_ROUTER_H
