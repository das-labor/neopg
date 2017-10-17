/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/openpgp/packet.h>

namespace NeoPG {
namespace OpenPGP {

void Packet::write(std::ostream& out) {
  if (m_header) {
    m_header->write(out);
  }
}

Packet::Packet() : m_header(0) {}

}  // namespace OpenPGP
}  // namespace NeoPG
