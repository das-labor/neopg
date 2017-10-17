/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#ifndef NEOPG_OPENPGP_LITERAL_DATA_PACKET_H__
#define NEOPG_OPENPGP_LITERAL_DATA_PACKET_H__

#include <neopg/openpgp/packet.h>
#include <vector>

namespace NeoPG {
namespace OpenPGP {

const std::string LITERAL_DATA_CONSOLE = "_CONSOLE";

enum class LiteralDataType : uint8_t {
  Binary = 0x62,
  Text = 0x74,
  Utf8 = 0x75,
  Local = 0x6c,
  OldLocal = 0x31
};

struct LiteralDataPacket : Packet {
  LiteralDataType m_data_type = LiteralDataType::Binary;
  std::string m_filename;
  uint32_t m_timestamp = 0;
  std::vector<uint8_t> m_data;

  void write(std::ostream& out) override;
  uint32_t body_length() override;
  PacketType type() override;
};

}  // namespace OpenPGP
}  // namespace NeoPG

#endif
