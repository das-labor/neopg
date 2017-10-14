#include <sstream>

#include "gtest/gtest.h"

#include "neopg/openpgp/tag.h"

using namespace NeoPG;

TEST(NeoPGTest, openpg_test) {
  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 3);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\x03");
  }

  {
    std::stringstream out;
    OpenPGP::OldPacketHeader tag(OpenPGP::PacketType::Marker, 3);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xa8\x03");
  }

  /* Examples from RFC 4880.  */
  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 100);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\x64");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 1723);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\xc5\xfb");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 100000);
    tag.write(out);
    ASSERT_EQ(out.str(), std::string("\xca\xff\x00\x01\x86\xa0", 6));
  }



}

