//
// Created by timber3252 on 7/30/19.
//

#include "packet.hpp"

void ra::OmeletHeader::set(uint8_t source, uint8_t type, uint16_t len) {
  protocol_id = PROTOCOL_OMELET;
  packet_source = source;
  packet_type = type;
  length = len;
  memset(virtual_ip_n, 0x00, sizeof virtual_ip_n);
}

void ra::OmeletHeader::set(uint8_t source, uint8_t type, uint16_t len,
                           ra::ipv6_address_t addr) {
  protocol_id = PROTOCOL_OMELET;
  packet_source = source;
  packet_type = type;
  length = len;
  std::copy(addr.begin(), addr.end(), virtual_ip_n);
}

ra::OmeletHeader::OmeletHeader() : protocol_id(PROTOCOL_OMELET), packet_source(0), packet_type(0), length(0) {
  memset(virtual_ip_n, 0x00, sizeof virtual_ip_n);
}

void ra::OmeletSimpleHeader::set(uint8_t source, uint8_t type, uint16_t len) {
  packet_source = source;
  packet_type = type;
  length = len;
}

ra::OmeletSimpleHeader::OmeletSimpleHeader()
    : packet_source(0), packet_type(0), length(0) {}

ra::IPv4RelayHeader::IPv4RelayHeader() : protocol_id(PROTOCOL_RELAY), packet_source(0), packet_type(0) {
  memset(dest_ip, 0x00, sizeof dest_ip);
}
