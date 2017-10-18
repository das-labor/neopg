/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/openpgp/user_id_packet.h>

namespace NeoPG {
namespace OpenPGP {

void UserIdPacket::write_body(std::ostream& out) {
  out.write(m_content.data(), m_content.size());
}

PacketType UserIdPacket::type() { return PacketType::UserID; }

}  // namespace OpenPGP
}  // namespace NeoPG
