/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/openpgp/header.h>
#include <neopg/openpgp/symmetrically_encrypted_integrity_protected_data_packet.h>

namespace NeoPG {
namespace OpenPGP {

void SymmetricallyEncryptedIntegrityProtectedDataPacket::write_body(
    std::ostream& out) const {
  out << (uint8_t)0x01;
  out.write((char*)m_data.data(), m_data.size());
}

PacketType SymmetricallyEncryptedIntegrityProtectedDataPacket::type() const {
  return PacketType::SymmetricallyEncryptedIntegrityProtectedData;
}

}  // namespace OpenPGP
}  // namespace NeoPG
