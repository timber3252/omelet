//
// Created by timber3252 on 7/30/19.
//

#ifndef OMELET_SRC_LINUX_BASE_R_MAP_HPP
#define OMELET_SRC_LINUX_BASE_R_MAP_HPP

#include "include.hpp"

namespace ra {

template <class Key, class Value> class RMap {
public:
  void insert(const Key &key, const Value &value) {
    mtx.lock();
    mp.insert(std::make_pair(key, value));
    mtx.unlock();
  }

  bool exist(const Key &key) {
    mtx.lock();
    bool ret = mp.count(key);
    mtx.unlock();
    return ret;
  }

  void remove(const Key &key) {
    mtx.lock();
    mp.erase(key);
    mtx.unlock();
  }

  int size() const { return mp.size(); }

  void clear() {
    mtx.lock();
    mp.clear();
    mtx.unlock();
  }

  std::optional<Value> query(const Key &key) {
    mtx.lock();
    bool exist = mp.count(key);

    if (exist) {
      Value res = mp[key];
      mtx.unlock();
      return res;
    } else {
      mtx.unlock();
      return {};
    }
  }

  void query_all(std::function<void(const Key &, const Value &)> resolve) {
    mtx.lock();
    for (const auto &i : mp) {
      resolve(i.first, i.second);
    }
    mtx.unlock();
  }

  template <class T>
  void query_all(T &arg,
                 std::function<void(const Key &, const Value &, T &)> resolve) {
    mtx.lock();
    for (const auto &i : mp) {
      resolve(i.first, i.second, arg);
    }
    mtx.unlock();
  }

  void swap(RMap<Key, Value> &other) {
    mtx.lock();
    mp.swap(other.mp);
    mtx.unlock();
  }

private:
  std::mutex mtx;
  std::map<Key, Value> mp;
};

} // namespace ra

#endif // OMELET_SRC_LINUX_BASE_R_MAP_HPP
