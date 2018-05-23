// OpenPGP format
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/packet.h>

#include <neopg/stream.h>

using namespace NeoPG;

void Packet::write(std::ostream& out,
                   packet_header_factory header_factory) const {
  if (m_header) {
    m_header->write(out);
  } else {
    CountingStream cnt;
    write_body(cnt);
    uint32_t len = cnt.bytes_written();
    std::unique_ptr<PacketHeader> default_header = header_factory(type(), len);
    default_header->write(out);
  }
  write_body(out);
}
