//
// Created by timber3252 on 7/30/19.
//

#ifndef OMELET_SRC_LINUX_BASE_INCLUDE_HPP
#define OMELET_SRC_LINUX_BASE_INCLUDE_HPP

// standard
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// posix
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

// openssl
#include <openssl/aes.h>

// linux
#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <net/if.h>

#endif // OMELET_SRC_LINUX_BASE_INCLUDE_HPP
