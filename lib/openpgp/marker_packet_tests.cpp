#include <sstream>

#include "gtest/gtest.h"

#include <neopg/marker_packet.h>

#include <memory>

using namespace NeoPG;

TEST(NeoPGTest, openpg_marker_packet_test) {
  {
    std::stringstream out;
    MarkerPacket packet;

    OldPacketHeader* header = new OldPacketHeader(PacketType::Marker, 3);

    packet.m_header = std::unique_ptr<PacketHeader>(header);
    packet.write(out);
    ASSERT_EQ(out.str(), "\xa8\x03PGP");
  }

  {
    std::stringstream out;
    MarkerPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(),
              "\xca\x03"
              "PGP");
  }
}
