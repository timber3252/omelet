//
// Created by timber3252 on 7/21/19.
//

#ifndef OMELET_THREAD_SAFE_H
#define OMELET_THREAD_SAFE_H

#include "global.h"

class Counter {
  std::mutex mtx;
  volatile int count;

 public:
  Counter() : count(0), mtx() {}

  int add() {
    mtx.lock();
    count += 1;
    int t = count;
    mtx.unlock();
    return t;
  }
};

class Allocator {
  std::mutex mtx;
  std::map<ipv4_address_t, Peer> mp;

 public:
  void insert(ipv4_address_t key_n, const Peer &value) {
    mtx.lock();
    mp.insert(std::make_pair(key_n, value));
    mtx.unlock();
  }

  bool exist(ipv4_address_t key_n) {
    mtx.lock();
    bool flag = mp.count(key_n);
    mtx.unlock();
    return flag;
  }

  void remove(ipv4_address_t key_n) {
    mtx.lock();
    mp.erase(key_n);
    mtx.unlock();
  }

  int size() const { return mp.size(); }

  int query_all(uint8_t *buf, uint16_t len) {
    mtx.lock();
    int n = size(), cnt = 0;
    if (10 * n > len) return -1;
    union {
      ipv4_address_t i;
      uint8_t s[4];
    } cur_n;
    for (const auto &i : mp) {
      cur_n.i = i.first;
      buf[cnt++] = cur_n.s[0];
      buf[cnt++] = cur_n.s[1];
      buf[cnt++] = cur_n.s[2];
      buf[cnt++] = cur_n.s[3];
      cur_n.i = i.second.ip_n;
      buf[cnt++] = cur_n.s[0];
      buf[cnt++] = cur_n.s[1];
      buf[cnt++] = cur_n.s[2];
      buf[cnt++] = cur_n.s[3];
      buf[cnt++] = i.second.port_n & 0x00ff;
      buf[cnt++] = (i.second.port_n & 0xff00) >> 8;
    }
    mtx.unlock();
    return cnt;
  }

  Peer query(ipv4_address_t key_n) {
    mtx.lock();
    Peer ret = mp[key_n];
    mtx.unlock();
    return ret;
  }
};

class Set {
  std::mutex mtx;
  std::set<int> s;

 public:
  int size() const { return s.size(); }

  void clear() {
    mtx.lock();
    s.clear();
    mtx.unlock();
  }

  void insert(int x) {
    mtx.lock();
    s.insert(x);
    mtx.unlock();
  }

  bool exist(int x) {
    mtx.lock();
    bool flag = s.count(x);
    mtx.unlock();
    return flag;
  }

  void remove(int x) {
    mtx.lock();
    s.erase(x);
    mtx.unlock();
  }

  int query_all(uint8_t *buf) {
    mtx.lock();
    int cnt = 0;
    for (auto i : s) {
      // 从高位到低位，按照网络字节顺序，以 127.0.0.1 为例
      buf[cnt++] = i & 0x000000ff;          // 127
      buf[cnt++] = (i & 0x0000ff00) >> 8;   // 0
      buf[cnt++] = (i & 0x00ff0000) >> 16;  // 0
      buf[cnt++] = (i & 0xff000000) >> 24;  // 1
    }
    mtx.unlock();
    return cnt;
  }
};

#endif  // OMELET_THREAD_SAFE_H
