// OpenPGP marker packet
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>

namespace NeoPG {

/// Represent an OpenPGP [marker
/// packet](https://tools.ietf.org/html/rfc4880#section-5.8).
///
/// Marker packets are obsolete.  NeoPG will never generate marker packets on
/// its own, and will ignore all marker packets it receives.  They are provided
/// here for completeness.
struct NEOPG_UNSTABLE_API MarkerPacket : Packet {
  void write_body(std::ostream& out) const override;
  PacketType type() const override;
};

}  // namespace NeoPG
