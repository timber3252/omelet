cmake_minimum_required(VERSION 3.14)
project(omelet)

set(CMAKE_CXX_STANDARD 17)

include_directories(src)

add_executable(server_linux src/linux/server/main.cpp src/linux/base/global.hpp src/linux/base/include.hpp src/linux/base/packet.cpp src/linux/base/packet.hpp src/linux/base/address.cpp src/linux/base/address.hpp src/linux/base/log.hpp src/linux/base/log.cpp src/linux/base/aes.cpp src/linux/base/aes.hpp src/linux/base/r_map.hpp)
target_link_libraries(server_linux crypto pthread)

add_executable(client_linux src/linux/client/main.cpp src/linux/base/global.hpp src/linux/base/include.hpp src/linux/base/packet.cpp src/linux/base/packet.hpp src/linux/base/address.cpp src/linux/base/address.hpp src/linux/base/log.hpp src/linux/base/log.cpp src/linux/base/aes.cpp src/linux/base/aes.hpp src/linux/base/r_map.hpp)
target_link_libraries(client_linux crypto pthread)

add_executable(relay_linux src/linux/relay/main.cpp src/linux/base/global.hpp src/linux/base/include.hpp src/linux/base/packet.cpp src/linux/base/packet.hpp src/linux/base/address.cpp src/linux/base/address.hpp src/linux/base/log.hpp src/linux/base/log.cpp src/linux/base/aes.cpp src/linux/base/aes.hpp src/linux/base/r_map.hpp)
target_link_libraries(relay_linux crypto pthread)
