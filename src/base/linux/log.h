//
// Created by timber3252 on 6/1/19.
//

#ifndef PROLINE_BACKEND_LOG_H
#define PROLINE_BACKEND_LOG_H

#include "global.h"

enum class LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3, Fatal = 4 };

const char level_str[][6] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

class ConsoleLog {
  class LogStream;

 public:
  ConsoleLog();

  virtual ~ConsoleLog() = default;

  LogStream operator()(LogLevel level);

 private:
  const tm *get_local_time();

  void endline(LogLevel level, std::string &&msg);

  void write(const tm *tm, const char *level, const char *msg);

  std::mutex _lock;
  tm _local_time;
};

class ConsoleLog::LogStream : public std::ostringstream {
  ConsoleLog &_logger;
  LogLevel _level;

 public:
  LogStream(ConsoleLog &logger, LogLevel level);

  LogStream(const LogStream &other);

  ~LogStream() override;
};

std::ostream &operator<<(std::ostream &stream, const tm *tm);

#endif  // PROLINE_BACKEND_LOG_H
