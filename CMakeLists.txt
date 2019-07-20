CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

PROJECT(omelet)

add_executable(server src/server/main.cpp src/base/linux/global.h src/base/linux/log.cpp src/base/linux/log.h src/base/linux/aes.h)
target_link_libraries(server pthread crypto)

add_executable(client_linux src/client/linux/main.cpp src/base/linux/global.h src/base/linux/log.cpp src/base/linux/log.h src/base/linux/aes.h src/base/linux/router.h)
target_link_libraries(client_linux pthread crypto)