#include <sstream>

#include "gtest/gtest.h"

#include <neopg/openpgp/user_id_packet.h>

#include <memory>

using namespace NeoPG;

TEST(NeoPGTest, openpg_user_id_packet_test) {
  {
    std::stringstream out;
    OpenPGP::UserIdPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCD\0", 2));
  }

  {
    std::stringstream out;
    OpenPGP::UserIdPacket packet;
    packet.m_content = "John Doe john.doe@example.com";
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCD\x1D"
                                     "John Doe john.doe@example.com",
                                     2 + packet.m_content.size()));
  }
}
