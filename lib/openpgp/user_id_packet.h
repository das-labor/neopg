// OpenPGP user ID packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>

namespace NeoPG {

/// Represent an OpenPGP [user ID
/// packet](https://tools.ietf.org/html/rfc4880#section-5.11).
///
/// User ID packets hold UTF-8 encoded text, often of the form "Name <Email>" or
/// "Name (Comment) <Email>". RFC 4880 does not impose a limit on its length,
/// GnuPG limits it to 2 KB.
class NEOPG_UNSTABLE_API UserIdPacket : public Packet {
 public:

  /// The suggested limit for the size of #m_content.  This limit is not
  /// enforced in this class.
  const size_t MAX_LENGTH = 2048;
  /// The user ID.
  std::string m_content;

  void write_body(std::ostream& out) const override;
  PacketType type() const override;

  UserIdPacket() = default;
};

}  // namespace NeoPG
