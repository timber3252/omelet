# omelet

A cross-platform dynamic virtual network. Basic functions have been implemented and tested. Originally designed for use in [swwind/proline](https://github.com/swwind/proline).

## Features

- IPv4 & IPv6 hybrid dynamic private network could be built based on stable server and relay
- Provide secure tunnel connection based on AES algorithm

## Dependencies

### Linux

- cmake (>= 3.10)
- gcc (>= 7, C++17 support)
- openssl (>= 1.0.0)

### Windows

## Requirements

- Server: support IPv6 dual-protocol stack
- Relay: static external IPv4 IP
- Client: IPv4 or IPv6, support tun device module

## Getting Started

### Linux

```bash
git clone https://github.com/timber3252/omelet
cd omelet

cmake -S . -B build
cd build
make
```

### Windows
