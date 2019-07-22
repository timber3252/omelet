CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

PROJECT(omelet)

add_executable(server src/server/main.cpp src/base/linux/global.h src/base/linux/log.cpp src/base/linux/log.h src/base/linux/aes.h src/base/linux/thread_safe.h)
target_link_libraries(server pthread crypto)

add_executable(client_linux src/client/linux/main.cpp src/base/linux/global.h src/base/linux/log.cpp src/base/linux/log.h src/base/linux/aes.h src/base/linux/router.h src/base/linux/thread_safe.h)
target_link_libraries(client_linux pthread crypto)

add_executable(random_aes_key util/random_aes_key.cpp)