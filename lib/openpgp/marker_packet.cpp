// OpenPGP marker packet (implementation)
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/marker_packet.h>

using namespace NeoPG;

void MarkerPacket::write_body(std::ostream& out) const { out << "PGP"; }

PacketType MarkerPacket::type() const { return PacketType::Marker; }
