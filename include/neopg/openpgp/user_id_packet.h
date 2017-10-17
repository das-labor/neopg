/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#ifndef NEOPG_OPENPGP_USER_ID_PACKET_H__
#define NEOPG_OPENPGP_USER_ID_PACKET_H__

#include <neopg/openpgp/packet.h>

namespace NeoPG {
namespace OpenPGP {

struct UserIdPacket : Packet {
  std::string m_content;

  void write(std::ostream& out) override;
  uint32_t body_length() override;
  PacketType type() override;
};

}  // namespace OpenPGP
}  // namespace NeoPG

#endif
