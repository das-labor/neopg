/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/openpgp/header.h>
#include <neopg/openpgp/literal_data_packet.h>

namespace NeoPG {
namespace OpenPGP {

void LiteralDataPacket::write_body(std::ostream& out) {
  out << (uint8_t)m_data_type;

  if (m_filename.length() > 255) {
    throw std::logic_error("filename too long");
  }

  out << (uint8_t)m_filename.size();
  out.write(m_filename.data(), m_filename.size());

  out << ((uint8_t)((m_timestamp >> 24) & 0xff))
      << ((uint8_t)((m_timestamp >> 16) & 0xff))
      << ((uint8_t)((m_timestamp >> 8) & 0xff))
      << ((uint8_t)(m_timestamp & 0xff));

  out.write((char*)m_data.data(), m_data.size());
}

PacketType LiteralDataPacket::type() { return PacketType::LiteralData; }

}  // namespace OpenPGP
}  // namespace NeoPG
