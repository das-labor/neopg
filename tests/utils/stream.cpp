/* Tests for stream functions
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/utils/stream.h>
#include "gtest/gtest.h"

using namespace NeoPG;

TEST(NeoPGTest, utils_stream_test) {
  {
    CountingStream out;
    ASSERT_EQ(out.bytes_written(), 0);
    out << (uint8_t)0x41;
    ASSERT_EQ(out.bytes_written(), 1);
    out << "NeoPG";
    ASSERT_EQ(out.bytes_written(), 6);
    out.write("Test", 4);
    ASSERT_EQ(out.bytes_written(), 10);
  }
}
