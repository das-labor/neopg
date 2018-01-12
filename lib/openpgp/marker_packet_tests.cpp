// OpenPGP marker packet (tests)
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/marker_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeoPGTest, openpg_marker_packet_test) {
  {
    // Test old packet header.
    std::stringstream out;
    MarkerPacket packet;
    OldPacketHeader* header = new OldPacketHeader(PacketType::Marker, 3);

    packet.m_header = std::unique_ptr<PacketHeader>(header);
    packet.write(out);
    ASSERT_EQ(out.str(), "\xa8\x03PGP");
  }

  {
    // Test new packet header.
    std::stringstream out;
    MarkerPacket packet;

    packet.write(out);
    ASSERT_EQ(out.str(), "\xca\x03PGP");
  }
}
