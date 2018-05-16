// OpenPGP packet header (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/packet_header.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_packet_header_test) {
  {
    std::stringstream out;
    NewPacketTag tag(PacketType::Marker);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca");
  }

  {
    std::stringstream out;
    NewPacketLength length(3);
    length.write(out);
    ASSERT_EQ(out.str(), "\x03");
  }

  {
    std::stringstream out;
    NewPacketTag tag(PacketType::Marker);
    NewPacketLength length(3);
    NewPacketHeader header(tag, length);
    header.write(out);
    ASSERT_EQ(out.str(), "\xca\x03");
  }

  {
    std::stringstream out;
    NewPacketHeader header(PacketType::Marker, 3);
    header.write(out);
    ASSERT_EQ(out.str(), "\xca\x03");
  }

  {
    std::stringstream out;
    OldPacketHeader header(PacketType::Marker, 3);
    header.write(out);
    ASSERT_EQ(out.str(), "\xa8\x03");
  }

  /* Examples from RFC 4880.  */
  {
    std::stringstream out;
    NewPacketLength length(100);
    length.write(out);
    ASSERT_EQ(out.str(), "\x64");
  }

  {
    std::stringstream out;
    NewPacketLength length(1723);
    length.write(out);
    ASSERT_EQ(out.str(), "\xc5\xfb");
  }

  {
    std::stringstream out;
    NewPacketLength length(100000);
    length.write(out);
    ASSERT_EQ(out.str(), std::string("\xff\x00\x01\x86\xa0", 5));
  }

  {
    std::stringstream out;
    NewPacketLength length(32768, PacketLengthType::Partial);
    length.write(out);
    ASSERT_EQ(out.str(), "\xef");
  }

  {
    std::stringstream out;
    NewPacketLength length(2, PacketLengthType::Partial);
    length.write(out);
    ASSERT_EQ(out.str(), "\xe1");
  }

  {
    std::stringstream out;
    NewPacketLength length(1, PacketLengthType::Partial);
    length.write(out);
    ASSERT_EQ(out.str(), "\xe0");
  }

  {
    std::stringstream out;
    NewPacketLength length(65536, PacketLengthType::Partial);
    length.write(out);
    ASSERT_EQ(out.str(), "\xf0");
  }

  {
    std::stringstream out;
    NewPacketLength length(1693, PacketLengthType::TwoOctet);
    length.write(out);
    ASSERT_EQ(out.str(), "\xc5\xdd");
  }

  /* Similar for old packet format, for comparison.  */
  {
    std::stringstream out;
    OldPacketHeader header(PacketType::Marker, 100);
    header.write(out);
    ASSERT_EQ(out.str(), "\xa8\x64");
  }

  {
    std::stringstream out;
    OldPacketHeader header(PacketType::Marker, 1723);
    header.write(out);
    ASSERT_EQ(out.str(), "\xa9\x06\xbb");
  }

  {
    std::stringstream out;
    OldPacketHeader header(PacketType::Marker, 100000);
    header.write(out);
    ASSERT_EQ(out.str(), std::string("\xaa\x00\x01\x86\xa0", 5));
  }

  /* Failures.  */
  { ASSERT_THROW(NewPacketTag((PacketType)64), std::logic_error); }

  {
    ASSERT_THROW(NewPacketLength(192, PacketLengthType::OneOctet),
                 std::logic_error);
  }

  {
    ASSERT_THROW(NewPacketLength(191, PacketLengthType::TwoOctet),
                 std::logic_error);
  }

  {
    ASSERT_THROW(NewPacketLength(3, PacketLengthType::Partial),
                 std::logic_error);
  }

  {
    ASSERT_THROW(OldPacketHeader(PacketType::UserAttribute, 0),
                 std::logic_error);
  }

  {
    ASSERT_THROW(
        OldPacketHeader(PacketType::Marker, 1 << 8, PacketLengthType::OneOctet),
        std::logic_error);
  }

  {
    ASSERT_THROW(OldPacketHeader(PacketType::Marker, 1 << 16,
                                 PacketLengthType::TwoOctet),
                 std::logic_error);
  }

  {
    ASSERT_THROW(
        OldPacketHeader(PacketType::Marker, 0, PacketLengthType::Indeterminate),
        std::logic_error);
  }

  {
    OldPacketHeader header(PacketType::Marker, 1, PacketLengthType::OneOctet);
    /* Force unsupported packet length type.  */
    header.m_length_type = PacketLengthType::Indeterminate;

    std::stringstream out;
    ASSERT_THROW(header.write(out), std::logic_error);
  }

  {
    OldPacketHeader header(PacketType::Marker, 0);
    header.set_length(0xff);
    ASSERT_EQ(header.m_length, 0xff);
  }

  {
    NewPacketLength pktlength(0);
    pktlength.set_length(0xff);
    ASSERT_EQ(pktlength.m_length, 0xff);
  }

  {
    ASSERT_EQ(OldPacketHeader::best_length_type(0), PacketLengthType::OneOctet);
    ASSERT_EQ(OldPacketHeader::best_length_type(0xff),
              PacketLengthType::OneOctet);
    ASSERT_EQ(OldPacketHeader::best_length_type(0x100),
              PacketLengthType::TwoOctet);
    ASSERT_EQ(OldPacketHeader::best_length_type(0xffff),
              PacketLengthType::TwoOctet);
    ASSERT_EQ(OldPacketHeader::best_length_type(0x10000),
              PacketLengthType::FourOctet);
    ASSERT_EQ(OldPacketHeader::best_length_type(0xffffffffU),
              PacketLengthType::FourOctet);
  }

  {
    ASSERT_EQ(NewPacketLength::best_length_type(0), PacketLengthType::OneOctet);
    ASSERT_EQ(NewPacketLength::best_length_type(0xbf),
              PacketLengthType::OneOctet);
    ASSERT_EQ(NewPacketLength::best_length_type(0xc0),
              PacketLengthType::TwoOctet);
    ASSERT_EQ(NewPacketLength::best_length_type(0x20bf),
              PacketLengthType::TwoOctet);
    ASSERT_EQ(NewPacketLength::best_length_type(0x20c0),
              PacketLengthType::FiveOctet);
    ASSERT_EQ(NewPacketLength::best_length_type(0xffffffffU),
              PacketLengthType::FiveOctet);
  }
}
