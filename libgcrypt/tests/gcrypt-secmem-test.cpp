#include "gcrypt.h"

#include "gtest/gtest.h"

extern "C" {
  int secmem_main(int argc, char* argv[]);
}

TEST(GcryptTest, secmem) {
    int result = secmem_main(0, NULL);
    ASSERT_EQ(result, 0);
}
