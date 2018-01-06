/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/packet_header.h>
#include <neopg/trust_packet.h>

namespace NeoPG {

void TrustPacket::write_body(std::ostream& out) const {
  out.write((char*)m_data.data(), m_data.size());
}

PacketType TrustPacket::type() const { return PacketType::Trust; }

}  // namespace NeoPG
