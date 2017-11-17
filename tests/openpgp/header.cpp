#include <sstream>

#include "gtest/gtest.h"

#include <neopg/openpgp/header.h>

#include <memory>

using namespace NeoPG;

TEST(NeoPGTest, openpg_header_test) {
  {
    std::stringstream out;
    OpenPGP::NewPacketTag tag(OpenPGP::PacketType::Marker);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketLength length(3);
    length.write(out);
    ASSERT_EQ(out.str(), "\x03");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketTag tag(OpenPGP::PacketType::Marker);
    OpenPGP::NewPacketLength length(3);
    OpenPGP::NewPacketHeader header(tag, length);
    header.write(out);
    ASSERT_EQ(out.str(), "\xca\x03");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader header(OpenPGP::PacketType::Marker, 3);
    header.write(out);
    ASSERT_EQ(out.str(), "\xca\x03");
  }

  {
    std::stringstream out;
    OpenPGP::OldPacketHeader header(OpenPGP::PacketType::Marker, 3);
    header.write(out);
    ASSERT_EQ(out.str(), "\xa8\x03");
  }

  /* Examples from RFC 4880.  */
  {
    std::stringstream out;
    OpenPGP::NewPacketLength length(100);
    length.write(out);
    ASSERT_EQ(out.str(), "\x64");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketLength length(1723);
    length.write(out);
    ASSERT_EQ(out.str(), "\xc5\xfb");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketLength length(100000);
    length.write(out);
    ASSERT_EQ(out.str(), std::string("\xff\x00\x01\x86\xa0", 5));
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketLength length(32768, OpenPGP::PacketLengthType::Partial);
    length.write(out);
    ASSERT_EQ(out.str(), "\xef");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketLength length(2, OpenPGP::PacketLengthType::Partial);
    length.write(out);
    ASSERT_EQ(out.str(), "\xe1");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketLength length(1, OpenPGP::PacketLengthType::Partial);
    length.write(out);
    ASSERT_EQ(out.str(), "\xe0");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketLength length(65536, OpenPGP::PacketLengthType::Partial);
    length.write(out);
    ASSERT_EQ(out.str(), "\xf0");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketLength length(1693, OpenPGP::PacketLengthType::TwoOctet);
    length.write(out);
    ASSERT_EQ(out.str(), "\xc5\xdd");
  }

  /* Similar for old packet format, for comparison.  */
  {
    std::stringstream out;
    OpenPGP::OldPacketHeader header(OpenPGP::PacketType::Marker, 100);
    header.write(out);
    ASSERT_EQ(out.str(), "\xa8\x64");
  }

  {
    std::stringstream out;
    OpenPGP::OldPacketHeader header(OpenPGP::PacketType::Marker, 1723);
    header.write(out);
    ASSERT_EQ(out.str(), "\xa9\x06\xbb");
  }

  {
    std::stringstream out;
    OpenPGP::OldPacketHeader header(OpenPGP::PacketType::Marker, 100000);
    header.write(out);
    ASSERT_EQ(out.str(), std::string("\xaa\x00\x01\x86\xa0", 5));
  }

  /* Failures.  */
  {
    ASSERT_THROW(OpenPGP::NewPacketTag((OpenPGP::PacketType)64),
                 std::logic_error);
  }

  {
    ASSERT_THROW(
        OpenPGP::NewPacketLength(192, OpenPGP::PacketLengthType::OneOctet),
        std::logic_error);
  }

  {
    ASSERT_THROW(
        OpenPGP::NewPacketLength(191, OpenPGP::PacketLengthType::TwoOctet),
        std::logic_error);
  }

  {
    ASSERT_THROW(
        OpenPGP::NewPacketLength(3, OpenPGP::PacketLengthType::Partial),
        std::logic_error);
  }

  {
    ASSERT_THROW(
        OpenPGP::OldPacketHeader(OpenPGP::PacketType::UserAttribute, 0),
        std::logic_error);
  }

  {
    ASSERT_THROW(OpenPGP::OldPacketHeader(OpenPGP::PacketType::Marker, 1 << 8,
                                          OpenPGP::PacketLengthType::OneOctet),
                 std::logic_error);
  }

  {
    ASSERT_THROW(OpenPGP::OldPacketHeader(OpenPGP::PacketType::Marker, 1 << 16,
                                          OpenPGP::PacketLengthType::TwoOctet),
                 std::logic_error);
  }

  {
    ASSERT_THROW(
        OpenPGP::OldPacketHeader(OpenPGP::PacketType::Marker, 0,
                                 OpenPGP::PacketLengthType::Indeterminate),
        std::logic_error);
  }

  {
    OpenPGP::OldPacketHeader header(OpenPGP::PacketType::Marker, 1,
                                    OpenPGP::PacketLengthType::OneOctet);
    /* Force unsupported packet length type.  */
    header.m_length_type = OpenPGP::PacketLengthType::Indeterminate;

    std::stringstream out;
    ASSERT_THROW(header.write(out), std::logic_error);
  }

  {
    OpenPGP::OldPacketHeader header(OpenPGP::PacketType::Marker, 0);
    header.set_length(0xff);
    ASSERT_EQ(header.m_length, 0xff);
  }

  {
    OpenPGP::NewPacketLength pktlength(0);
    pktlength.set_length(0xff);
    ASSERT_EQ(pktlength.m_length, 0xff);
  }

  {
    ASSERT_EQ(OpenPGP::OldPacketHeader::best_length_type(0),
              OpenPGP::PacketLengthType::OneOctet);
    ASSERT_EQ(OpenPGP::OldPacketHeader::best_length_type(0xff),
              OpenPGP::PacketLengthType::OneOctet);
    ASSERT_EQ(OpenPGP::OldPacketHeader::best_length_type(0x100),
              OpenPGP::PacketLengthType::TwoOctet);
    ASSERT_EQ(OpenPGP::OldPacketHeader::best_length_type(0xffff),
              OpenPGP::PacketLengthType::TwoOctet);
    ASSERT_EQ(OpenPGP::OldPacketHeader::best_length_type(0x10000),
              OpenPGP::PacketLengthType::FourOctet);
    ASSERT_EQ(OpenPGP::OldPacketHeader::best_length_type(0xffffffffU),
              OpenPGP::PacketLengthType::FourOctet);
  }

  {
    ASSERT_EQ(OpenPGP::NewPacketLength::best_length_type(0),
              OpenPGP::PacketLengthType::OneOctet);
    ASSERT_EQ(OpenPGP::NewPacketLength::best_length_type(0xbf),
              OpenPGP::PacketLengthType::OneOctet);
    ASSERT_EQ(OpenPGP::NewPacketLength::best_length_type(0xc0),
              OpenPGP::PacketLengthType::TwoOctet);
    ASSERT_EQ(OpenPGP::NewPacketLength::best_length_type(0x20bf),
              OpenPGP::PacketLengthType::TwoOctet);
    ASSERT_EQ(OpenPGP::NewPacketLength::best_length_type(0x20c0),
              OpenPGP::PacketLengthType::FiveOctet);
    ASSERT_EQ(OpenPGP::NewPacketLength::best_length_type(0xffffffffU),
              OpenPGP::PacketLengthType::FiveOctet);
  }
}
