// OpenPGP user attribute packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/packet_header.h>
#include <neopg/stream.h>
#include <neopg/user_attribute_packet.h>

namespace NeoPG {

void UserAttributePacket::write_body(std::ostream& out) const {
  CountingStream cnt;
  write_attribute(cnt);
  /* We have to add 1 for the subpacket type.  */
  uint32_t len = 1 + cnt.bytes_written();
  NewPacketLength subpacket_length(len);

  subpacket_length.write(out);
  out << (uint8_t)attribute_type();
  write_attribute(out);
}

PacketType UserAttributePacket::type() const {
  return PacketType::UserAttribute;
}

/* Image Subpacket */

void ImageAttributeSubpacket::write_attribute(std::ostream& out) const {
  /* Little-endian image header length ("historical accident").  */
  out << (uint8_t)0x10 << (uint8_t)0x00;
  /* Image header version.  */
  out << (uint8_t)0x01;
  /* Encoding.  */
  out << (uint8_t)ImageEncoding::JPEG;
  /* Reserved.  */
  out << std::string(12, '\x00');

  out.write((char*)m_data.data(), m_data.size());
}

UserAttributeType ImageAttributeSubpacket::attribute_type() const {
  return UserAttributeType::Image;
}

}  // namespace NeoPG
