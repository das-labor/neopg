#include "gpg-error.h"

#include "gtest/gtest.h"

int b64dec_main(int argc, char* argv[]);
int printf_main(int argc, char* argv[]);
int strerror_main(int argc, char* argv[]);
int syserror_main(int argc, char* argv[]);

TEST(GpgErrorTest, ErrorType) {
  gpg_error_t err = GPG_ERR_USER_1;
  ASSERT_EQ(GPG_ERR_USER_1, err);
}

TEST(GpgErrorTest, b64dec) {
  int result = b64dec_main(0, NULL);
  ASSERT_EQ(result, 0);
}

TEST(GpgErrorTest, printf) {
  int result = printf_main(0, NULL);
  ASSERT_EQ(result, 0);
}

TEST(GpgErrorTest, strerror) {
  int result = strerror_main(0, NULL);
  ASSERT_EQ(result, 0);
}

TEST(GpgErrorTest, syserror) {
  int result = syserror_main(0, NULL);
  ASSERT_EQ(result, 0);
}
