/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/marker_packet.h>

namespace NeoPG {

void MarkerPacket::write_body(std::ostream& out) const {
  out << (uint8_t)0x50;
  out << (uint8_t)0x47;
  out << (uint8_t)0x50;
}

PacketType MarkerPacket::type() const { return PacketType::Marker; }

}  // namespace NeoPG
