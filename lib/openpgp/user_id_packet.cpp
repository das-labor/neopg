// OpenPGP user ID packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/user_id_packet.h>

using namespace NeoPG;

void UserIdPacket::write_body(std::ostream& out) const {
  out.write(m_content.data(), m_content.size());
}

PacketType UserIdPacket::type() const { return PacketType::UserId; }
