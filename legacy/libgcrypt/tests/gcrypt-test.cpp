#include "gcrypt.h"

#include "gtest/gtest.h"

  int hmac_main(int argc, char* argv[]);

TEST(GcryptTest, hmac) {
    int result = hmac_main(0, NULL);
    ASSERT_EQ(result, 0);
}
