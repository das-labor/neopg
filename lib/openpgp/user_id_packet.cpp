/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/openpgp/user_id_packet.h>

namespace NeoPG {
namespace OpenPGP {

void UserIdPacket::write(std::ostream& out) {
  Packet::write(out);

  out.write(m_content.data(), m_content.size());
}

PacketType UserIdPacket::type() { return PacketType::UserID; }

uint32_t UserIdPacket::body_length() { return m_content.size(); }

}  // namespace OpenPGP
}  // namespace NeoPG
