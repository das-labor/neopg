#include "gpg-error.h"

#include "gtest/gtest.h"

extern "C" {
  int b64dec_main(int argc, char* argv[]);
  int lock_main(int argc, char* argv[]);
  int poll_main(int argc, char* argv[]);
  int printf_main(int argc, char* argv[]);
  int strerror_main(int argc, char* argv[]);
  int syserror_main(int argc, char* argv[]);
}

TEST(GpgErrorTest, ErrorType) {
    gpg_error_t err = gpg_err_make(GPG_ERR_SOURCE_USER_1, GPG_ERR_USER_1);
    ASSERT_EQ(GPG_ERR_SOURCE_USER_1, gpg_err_source(err));
    ASSERT_EQ(GPG_ERR_USER_1, gpg_err_code(err));
}

TEST(GpgErrorTest, b64dec) {
    int result = b64dec_main(0, NULL);
    ASSERT_EQ(result, 0);
}

TEST(GpgErrorTest, lock) {
    int result = lock_main(0, NULL);
    ASSERT_EQ(result, 0);
}

TEST(GpgErrorTest, poll) {
    int result = poll_main(0, NULL);
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
