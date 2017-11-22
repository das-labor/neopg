#include "ksba.h"

#include "gtest/gtest.h"

int oid_main(int argc, char* argv[]);
int crl_parser_main(int argc, char* argv[]);
int dnparser_main(int argc, char* argv[]);

TEST(KsbaTest, oid) {
  int result = oid_main(0, NULL);
  ASSERT_EQ(result, 0);
}

TEST(KsbaTest, crl_parser) {
  int result = crl_parser_main(0, NULL);
  ASSERT_EQ(result, 0);
}

TEST(KsbaTest, dnparser) {
  int result = dnparser_main(0, NULL);
  ASSERT_EQ(result, 0);
}
