/* Tests for openpgp parser
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/openpgp.h>
#include <tao/pegtl.hpp>
#include <tao/pegtl/argv_input.hpp>
#include "gtest/gtest.h"

using namespace NeoPG;
using namespace tao::neopg_pegtl;

namespace NeoPG {

TEST(NeoPGTest, parser_openpgp_test) {
  {
    std::string t = "\x80\x80\x80";
    string_input<> in(t, "parser_openpgp_test");

    Parser::OpenPGP::state st;
    parse<Parser::OpenPGP::grammar, Parser::OpenPGP::action>(in, st);

    ASSERT_EQ(st.packets.size(), 3);
  }
}
}
