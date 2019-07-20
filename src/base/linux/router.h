//
// Created by timber3252 on 7/20/19.
//

#ifndef OMELET_ROUTER_H
#define OMELET_ROUTER_H

#include "global.h"

class Router {
public:
  struct RouterNode {
    RouterNode() : ip(0), port(0) { ch[0] = ch[1] = 0; }

    RouterNode *ch[2];
    uint32_t ip;
    uint16_t port;
  };

  Router() {
    rt = new RouterNode();
  }

  void insert(uint32_t key, uint32_t ip, uint16_t port) {
    mtx.lock();
    RouterNode *now = rt;
    for (int i = 0; i < 32; ++i, key >>= 1) {
      int nxt = key & 1;
      if (now->ch[nxt] == nullptr)
        now->ch[nxt] = new RouterNode();
      now = now->ch[nxt];
    }
    now->ip = ip, now->port = port;
    mtx.unlock();
  }

  RouterNode* query(uint32_t key) {
    RouterNode *now = rt;
    for (int i = 0; i < 32; ++i, key >>= 1) {
      int nxt = key & 1;
      if (now->ch[nxt] == nullptr)
        return nullptr;
      now = now->ch[nxt];
    }
    return now;
  }

private:
  std::mutex mtx;
  RouterNode *rt;

};


#endif //OMELET_ROUTER_H
