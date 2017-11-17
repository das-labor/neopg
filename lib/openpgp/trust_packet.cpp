/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/openpgp/header.h>
#include <neopg/openpgp/trust_packet.h>

namespace NeoPG {
namespace OpenPGP {

void TrustPacket::write_body(std::ostream& out) const {
  out.write((char*)m_data.data(), m_data.size());
}

PacketType TrustPacket::type() const { return PacketType::Trust; }

}  // namespace OpenPGP
}  // namespace NeoPG
