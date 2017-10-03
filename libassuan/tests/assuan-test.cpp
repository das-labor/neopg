#include "assuan.h"

#include "gtest/gtest.h"

  int fdpassing_main(int argc, char* argv[]);

TEST(AssuanTest, fdpassing) {
    int result = fdpassing_main(0, NULL);
    ASSERT_EQ(result, 0);
}
