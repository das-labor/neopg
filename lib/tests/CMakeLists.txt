# NeoPG - tests
# Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

add_executable(test-libneopg
  # Pure unit tests are located alongside the implementation.
  ../openpgp/packet_header_tests.cpp
  ../openpgp/marker_packet_tests.cpp
  ../openpgp/literal_data_packet_tests.cpp
  ../openpgp/user_id_packet_tests.cpp
  ../openpgp/user_attribute_packet_tests.cpp
  ../openpgp/modification_detection_code_packet_tests.cpp
  ../openpgp/multiprecision_integer_tests.cpp
  ../openpgp/object_identifier_tests.cpp
  ../openpgp/symmetrically_encrypted_integrity_protected_data_packet_tests.cpp
  ../openpgp/symmetrically_encrypted_data_packet_tests.cpp
  ../openpgp/compressed_data_packet_tests.cpp
  ../openpgp/trust_packet_tests.cpp
  ../utils/stream_tests.cpp
  ../parser/openpgp_tests.cpp
  ../parser/parser_input_tests.cpp
  ../proto/uri_tests.cpp
  ../proto/http_tests.cpp
)

target_include_directories(test-libneopg
  PRIVATE
  ${JSON_INCLUDE_DIR}
)

target_link_libraries(test-libneopg
  PRIVATE
  neopg
  GTest::GTest GTest::Main
)

add_test(LibNeoPGTest test-libneopg
  COMMAND test-libneopg test_xml_output --gtest_output=xml:test-libneopg.xml
)
add_dependencies(tests test-libneopg)
