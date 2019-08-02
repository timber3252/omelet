//
// Created by timber3252 on 6/2/19.
//

#include "linux/base/log.hpp"

ra::ConsoleLog::LogStream ra::ConsoleLog::operator()(LogLevel level) {
  return ConsoleLog::LogStream(*this, level);
}

const tm *ra::ConsoleLog::get_local_time() {
  auto now = std::chrono::system_clock::now();
  auto in_time_t = std::chrono::system_clock::to_time_t(now);
#ifdef WIN32
  localtime_s(&local_time_, &in_time_t);
#else
  localtime_r(&in_time_t, &_local_time);
#endif
  return &_local_time;
}

void ra::ConsoleLog::endline(LogLevel level, std::string &&msg) {
  _lock.lock();
  write(get_local_time(), level_str[static_cast<int>(level)], msg.c_str());
  _lock.unlock();
}

ra::ConsoleLog::ConsoleLog() : _lock(), _local_time() {
  std::ios::sync_with_stdio(false);
}

ra::ConsoleLog::LogStream::LogStream(ConsoleLog &logger, LogLevel level)
    : _logger(logger), _level(level) {}

ra::ConsoleLog::LogStream::LogStream(const ConsoleLog::LogStream &other)
    : _logger(other._logger), _level(other._level) {}

ra::ConsoleLog::LogStream::~LogStream() {
  _logger.endline(_level, std::move(str()));
}

std::ostream &operator<<(std::ostream &stream, const tm *tm) {
  return stream << 1900 + tm->tm_year << '-' << std::setfill('0')
                << std::setw(2) << tm->tm_mon + 1 << '-' << std::setfill('0')
                << std::setw(2) << tm->tm_mday << ' ' << std::setfill('0')
                << std::setw(2) << tm->tm_hour << ':' << std::setfill('0')
                << std::setw(2) << tm->tm_min << ':' << std::setfill('0')
                << std::setw(2) << tm->tm_sec;
}

void ra::ConsoleLog::write(const tm *tm, const char *level, const char *msg) {
  bool err = !strcmp(level, "FATAL") || !strcmp(level, "ERROR");

  // cross-platform ?
  if (err) {
    std::cout << "\033[33m";
  }

  std::cout << '[' << tm << ']' << '[' << level << ']' << '\t' << msg
            << std::endl;

  if (err) {
    std::cout << "\033[0m";
  }

  std::cout.flush();
}
