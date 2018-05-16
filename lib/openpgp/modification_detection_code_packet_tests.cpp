// OpenPGP MDC packet (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/modification_detection_code_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_modification_detection_code_packet_test) {
  {
    // Must be new packet header, so we don't test old.
    std::stringstream out;
    ModificationDetectionCodePacket packet;
    packet.m_data = std::vector<uint8_t>{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14};
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xD3\x14"
                                     "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
                                     "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14",
                                     22));
  }

  {
    // Failures.
    std::stringstream out;
    ModificationDetectionCodePacket packet;
    ASSERT_THROW(packet.write(out), std::logic_error);
  }
}
