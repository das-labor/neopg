// OpenPGP MDC packet
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>

#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [modification detection code
/// packet](https://tools.ietf.org/html/rfc4880#section-5.14).
///
/// MDC packets add integrity to RFC 4880 encryption.  RFC 4880 requires that
/// the MDC is 20-bytes (::write_body throws a logic_error exception if that is
/// not true). It also requires that the packet uses a NewPacketHeader with
/// PacketLengthType::OneOctet (this is not enforced by this class, but it is
/// the default behaviour).
struct NEOPG_UNSTABLE_API ModificationDetectionCodePacket : Packet {
  /// The MDC data, must be 20 bytes (SHA-1).
  std::vector<uint8_t> m_data;

  void write_body(std::ostream& out) const override;
  PacketType type() const override;
};

}  // namespace NeoPG
