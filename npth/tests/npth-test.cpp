#include "npth.h"

#include "gtest/gtest.h"

extern "C" {
  int fork_main(int argc, char* argv[]);
  int mutex_main(int argc, char* argv[]);
  int thread_main(int argc, char* argv[]);
}

TEST(nPthTest, fork) {
    int result = fork_main(0, NULL);
    ASSERT_EQ(result, 0);
}

TEST(nPthTest, mutex) {
    int result = mutex_main(0, NULL);
    ASSERT_EQ(result, 0);
}

TEST(nPthTest, thread) {
    int result = thread_main(0, NULL);
    ASSERT_EQ(result, 0);
}
