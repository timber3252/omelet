# omelet

A cross-platform dynamic virtual network. Currently it is in the initial development stage.

[TOC]

## Features

- the virtual network could be able to work in the Internet based on stable external server
- provide encrypted packet transmission tunnel between nodes based on tun device

## TODO

- [ ] support for windows
- [ ] send by private address if clients were in the same LAN
- [ ] limit router update speed ( >= 5s a time )
- [ ] server close notification
- [ ] null constructor that called by [] operation 

## API

The packet is declared as following. 

```cpp
struct OmeletSimpleProtoHeader {
  uint8_t packet_source;
  uint8_t packet_type;
  uint16_t length;
};

template <size_t size>
struct SimplePacket {
  OmeletSimpleProtoHeader header; // 12 bytes
  uint8_t data[size]; // size bytes
};
```

### GET_VIRTUAL_IP

```text
Request Packet (4 bytes)
  packet_source = PACKET_APPLICATIONS (0xd3)
  packet_type = PACKET_TYPE_LOCAL_GET_VIRTUAL_IP | PACKET_NEED_REPLY (0x89)
  length = 4 (0x00 0x04)

Reply Packet (8 bytes)
  packet_source = PACKET_APPLICATIONS (0xd3)
  packet_type = PACKET_TYPE_LOCAL_GET_VIRTUAL_IP | PACKET_NO_REPLY (0x49)
  length = 8 (0x00 0x08)
  data = [0x7f, 0x00, 0x00, 0x01] (example: 127.0.0.1)
```

### GET_ROUTERS

```text
Request Packet (4 bytes)
  packet_source = PACKET_APPLICATIONS (0xd3)
  packet_type = PACKET_TYPE_LOCAL_GET_ROUTERS | PACKET_NEED_REPLY (0x88)
  length = 4 (0x00 0x04)

Reply Packet (4 + n * 4 bytes, n is the number of clients)
  packet_source = PACKET_APPLICATIONS (0xd3)
  packet_type = PACKET_TYPE_LOCAL_GET_ROUTERS | PACKET_NO_REPLY (0x48)
  length = 12 (0x00 0x0c) (example: n = 2)
  data = [0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01]
```

## See Also

[swwind/proline](https://github.com/swwind/proline)