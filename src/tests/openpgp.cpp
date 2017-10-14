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
}

