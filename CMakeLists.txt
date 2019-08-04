cmake_minimum_required(VERSION 3.10)
project(omelet)

set(CMAKE_CXX_STANDARD 17)

include_directories(linux)

add_executable(server_linux linux/src/server/main.cpp linux/src/base/global.hpp linux/src/base/include.hpp linux/src/base/packet.cpp linux/src/base/packet.hpp linux/src/base/address.cpp linux/src/base/address.hpp linux/src/base/log.hpp linux/src/base/log.cpp linux/src/base/aes.cpp linux/src/base/aes.hpp linux/src/base/r_map.hpp)
target_link_libraries(server_linux crypto pthread)

add_executable(client_linux linux/src/client/main.cpp linux/src/base/global.hpp linux/src/base/include.hpp linux/src/base/packet.cpp linux/src/base/packet.hpp linux/src/base/address.cpp linux/src/base/address.hpp linux/src/base/log.hpp linux/src/base/log.cpp linux/src/base/aes.cpp linux/src/base/aes.hpp linux/src/base/r_map.hpp)
target_link_libraries(client_linux crypto pthread)

add_executable(relay_linux linux/src/relay/main.cpp linux/src/base/global.hpp linux/src/base/include.hpp linux/src/base/packet.cpp linux/src/base/packet.hpp linux/src/base/address.cpp linux/src/base/address.hpp linux/src/base/log.hpp linux/src/base/log.cpp linux/src/base/aes.cpp linux/src/base/aes.hpp linux/src/base/r_map.hpp)
target_link_libraries(relay_linux crypto pthread)

add_executable(random_aes_key linux/util/random_aes_key.cpp)
