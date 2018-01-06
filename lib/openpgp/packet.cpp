/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/packet.h>
#include <neopg/stream.h>

namespace NeoPG {

void Packet::write(std::ostream& out) const {
  if (m_header) {
    m_header->write(out);
  } else {
    CountingStream cnt;
    write_body(cnt);
    uint32_t len = cnt.bytes_written();
    NewPacketHeader default_header(type(), len);
    default_header.write(out);
  }
  write_body(out);
}

}  // namespace NeoPG
