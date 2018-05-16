# NeoPG - tests
# Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

add_executable(test-libneopg
  # Pure unit tests are located alongside the implementation.
  ../openpgp/compressed_data_packet_tests.cpp
  ../openpgp/literal_data_packet_tests.cpp
  ../openpgp/marker_packet_tests.cpp
  ../openpgp/modification_detection_code_packet_tests.cpp
  ../openpgp/multiprecision_integer_tests.cpp
  ../openpgp/object_identifier_tests.cpp
  ../openpgp/packet_header_tests.cpp
  ../openpgp/public_key_packet_tests.cpp
  ../openpgp/public_key/data/v3_public_key_data_tests.cpp
  ../openpgp/public_key/data/v4_public_key_data_tests.cpp
  ../openpgp/public_key/material/dsa_public_key_material_tests.cpp
  ../openpgp/public_key/material/ecdh_public_key_material_tests.cpp
  ../openpgp/public_key/material/ecdsa_public_key_material_tests.cpp
  ../openpgp/public_key/material/eddsa_public_key_material_tests.cpp
  ../openpgp/public_key/material/elgamal_public_key_material_tests.cpp
  ../openpgp/public_key/material/raw_public_key_material_tests.cpp
  ../openpgp/public_key/material/rsa_public_key_material_tests.cpp
  ../openpgp/public_key/public_key_data_tests.cpp
  ../openpgp/public_key/public_key_material_tests.cpp
  ../openpgp/public_subkey_packet_tests.cpp
  ../openpgp/symmetrically_encrypted_data_packet_tests.cpp
  ../openpgp/symmetrically_encrypted_integrity_protected_data_packet_tests.cpp
  ../openpgp/trust_packet_tests.cpp
  ../openpgp/user_attribute_packet_tests.cpp
  ../openpgp/user_id_packet_tests.cpp
  ../parser/openpgp_tests.cpp
  ../parser/parser_input_tests.cpp
  ../proto/http_tests.cpp
  ../proto/uri_tests.cpp
  ../utils/stream_tests.cpp
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

add_test(NeopgTest test-libneopg
  COMMAND test-libneopg test_xml_output --gtest_output=xml:test-libneopg.xml
)
add_dependencies(tests test-libneopg)
