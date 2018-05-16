// OpenPGP user attribute packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>
#include <vector>

namespace NeoPG {

enum class NEOPG_UNSTABLE_API UserAttributeType : uint8_t {
  Image = 0x01,
  Private_100 = 0x64,
  Private_101 = 0x65,
  Private_102 = 0x66,
  Private_103 = 0x67,
  Private_104 = 0x68,
  Private_105 = 0x69,
  Private_106 = 0x6a,
  Private_107 = 0x6b,
  Private_108 = 0x6c,
  Private_109 = 0x6d,
  Private_110 = 0x6e,
};

struct NEOPG_UNSTABLE_API UserAttributePacket : Packet {
  void write_body(std::ostream& out) const override;
  PacketType type() const override;

  virtual void write_attribute(std::ostream& out) const = 0;
  virtual UserAttributeType attribute_type() const = 0;
};

/* Image Attribute Subpacket.  */

enum class NEOPG_UNSTABLE_API ImageEncoding : uint8_t {
  JPEG = 0x01,
  Private_100 = 0x64,
  Private_101 = 0x65,
  Private_102 = 0x66,
  Private_103 = 0x67,
  Private_104 = 0x68,
  Private_105 = 0x69,
  Private_106 = 0x6a,
  Private_107 = 0x6b,
  Private_108 = 0x6c,
  Private_109 = 0x6d,
  Private_110 = 0x6e,
};

struct NEOPG_UNSTABLE_API ImageAttributeSubpacket : UserAttributePacket {
  std::vector<uint8_t> m_data;
  void write_attribute(std::ostream& out) const override;
  UserAttributeType attribute_type() const override;
};

}  // namespace NeoPG
