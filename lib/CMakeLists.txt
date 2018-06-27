# NeoPG - library
# Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

FIND_PACKAGE(Boost COMPONENTS date_time REQUIRED)

# libneopg

set(NEOPG_INCLUDE ../include)

set(NeopgHeaders
  crypto/rng.h
  openpgp/compressed_data_packet.h
  openpgp/literal_data_packet.h
  openpgp/marker_packet.h
  openpgp/modification_detection_code_packet.h
  openpgp/multiprecision_integer.h
  openpgp/object_identifier.h
  openpgp/packet.h
  openpgp/packet_header.h
  openpgp/public_key/data/v3_public_key_data.h
  openpgp/public_key/data/v4_public_key_data.h
  openpgp/public_key/material/dsa_public_key_material.h
  openpgp/public_key/material/ecdh_public_key_material.h
  openpgp/public_key/material/ecdsa_public_key_material.h
  openpgp/public_key/material/eddsa_public_key_material.h
  openpgp/public_key/material/elgamal_public_key_material.h
  openpgp/public_key/material/raw_public_key_material.h
  openpgp/public_key/material/rsa_public_key_material.h
  openpgp/public_key/public_key_data.h
  openpgp/public_key/public_key_material.h
  openpgp/public_key_packet.h
  openpgp/public_subkey_packet.h
  openpgp/raw_packet.h
  openpgp/signature_packet.h
  openpgp/signature/signature_data.h
  openpgp/signature/data/v3_signature_data.h
  openpgp/signature/data/v4_signature_data.h
  openpgp/signature/data/v4_signature_subpacket_data.h
  openpgp/signature/material/raw_signature_material.h
  openpgp/signature/material/rsa_signature_material.h
  openpgp/signature/material/dsa_signature_material.h
  openpgp/signature/material/ecdsa_signature_material.h
  openpgp/signature/material/eddsa_signature_material.h
  openpgp/signature/signature_material.h
  openpgp/signature/signature_subpacket.h
  openpgp/signature/subpacket/embedded_signature_subpacket.h
  openpgp/signature/subpacket/exportable_certification_subpacket.h
  openpgp/signature/subpacket/features_subpacket.h
  openpgp/signature/subpacket/issuer_subpacket.h
  openpgp/signature/subpacket/key_expiration_time_subpacket.h
  openpgp/signature/subpacket/key_flags_subpacket.h
  openpgp/signature/subpacket/key_server_preferences_subpacket.h
  openpgp/signature/subpacket/notation_data_subpacket.h
  openpgp/signature/subpacket/policy_uri_subpacket.h
  openpgp/signature/subpacket/preferred_compression_algorithms_subpacket.h
  openpgp/signature/subpacket/preferred_hash_algorithms_subpacket.h
  openpgp/signature/subpacket/preferred_key_server_subpacket.h
  openpgp/signature/subpacket/preferred_symmetric_algorithms_subpacket.h
  openpgp/signature/subpacket/primary_user_id_subpacket.h
  openpgp/signature/subpacket/raw_signature_subpacket.h
  openpgp/signature/subpacket/reason_for_revocation_subpacket.h
  openpgp/signature/subpacket/regular_expression_subpacket.h
  openpgp/signature/subpacket/revocable_subpacket.h
  openpgp/signature/subpacket/revocation_key_subpacket.h
  openpgp/signature/subpacket/signature_creation_time_subpacket.h
  openpgp/signature/subpacket/signature_expiration_time_subpacket.h
  openpgp/signature/subpacket/signature_target_subpacket.h
  openpgp/signature/subpacket/signers_user_id_subpacket.h
  openpgp/signature/subpacket/trust_signature_subpacket.h
  openpgp/symmetrically_encrypted_data_packet.h
  openpgp/symmetrically_encrypted_integrity_protected_data_packet.h
  openpgp/trust_packet.h
  openpgp/user_attribute/subpacket/image_attribute_subpacket.h
  openpgp/user_attribute/subpacket/raw_user_attribute_subpacket.h
  openpgp/user_attribute/user_attribute_subpacket.h
  openpgp/user_attribute_packet.h
  openpgp/user_id_packet.h
  parser/openpgp.h
  parser/parser_error.h
  parser/parser_input.h
  parser/parser_position.h
  proto/http.h
  proto/uri.h
  utils/common.h
  utils/stream.h
  utils/time.h
)
add_library(neopg
  crypto/rng.cpp
  include/neopg/intern/cplusplus.h
  openpgp/compressed_data_packet.cpp
  openpgp/literal_data_packet.cpp
  openpgp/marker_packet.cpp
  openpgp/modification_detection_code_packet.cpp
  openpgp/multiprecision_integer.cpp
  openpgp/object_identifier.cpp
  openpgp/packet.cpp
  openpgp/packet_header.cpp
  openpgp/public_key_packet.cpp
  openpgp/public_key/data/v3_public_key_data.cpp
  openpgp/public_key/data/v4_public_key_data.cpp
  openpgp/public_key/material/dsa_public_key_material.cpp
  openpgp/public_key/material/ecdh_public_key_material.cpp
  openpgp/public_key/material/ecdsa_public_key_material.cpp
  openpgp/public_key/material/eddsa_public_key_material.cpp
  openpgp/public_key/material/elgamal_public_key_material.cpp
  openpgp/public_key/material/raw_public_key_material.cpp
  openpgp/public_key/material/rsa_public_key_material.cpp
  openpgp/public_key/public_key_data.cpp
  openpgp/public_key/public_key_material.cpp
  openpgp/public_subkey_packet.cpp
  openpgp/raw_packet.cpp
  openpgp/signature_packet.cpp
  openpgp/signature/data/v3_signature_data.cpp
  openpgp/signature/data/v4_signature_data.cpp
  openpgp/signature/data/v4_signature_subpacket_data.cpp
  openpgp/signature/material/raw_signature_material.cpp
  openpgp/signature/material/rsa_signature_material.cpp
  openpgp/signature/material/dsa_signature_material.cpp
  openpgp/signature/material/ecdsa_signature_material.cpp
  openpgp/signature/material/eddsa_signature_material.cpp
  openpgp/signature/signature_data.cpp
  openpgp/signature/signature_material.cpp
  openpgp/signature/signature_subpacket.cpp
  openpgp/signature/subpacket/embedded_signature_subpacket.cpp
  openpgp/signature/subpacket/exportable_certification_subpacket.cpp
  openpgp/signature/subpacket/features_subpacket.cpp
  openpgp/signature/subpacket/issuer_subpacket.cpp
  openpgp/signature/subpacket/key_expiration_time_subpacket.cpp
  openpgp/signature/subpacket/key_flags_subpacket.cpp
  openpgp/signature/subpacket/key_server_preferences_subpacket.cpp
  openpgp/signature/subpacket/notation_data_subpacket.cpp
  openpgp/signature/subpacket/policy_uri_subpacket.cpp
  openpgp/signature/subpacket/preferred_compression_algorithms_subpacket.cpp
  openpgp/signature/subpacket/preferred_hash_algorithms_subpacket.cpp
  openpgp/signature/subpacket/preferred_key_server_subpacket.cpp
  openpgp/signature/subpacket/preferred_symmetric_algorithms_subpacket.cpp
  openpgp/signature/subpacket/primary_user_id_subpacket.cpp
  openpgp/signature/subpacket/raw_signature_subpacket.cpp
  openpgp/signature/subpacket/reason_for_revocation_subpacket.cpp
  openpgp/signature/subpacket/regular_expression_subpacket.cpp
  openpgp/signature/subpacket/revocable_subpacket.cpp
  openpgp/signature/subpacket/revocation_key_subpacket.cpp
  openpgp/signature/subpacket/signature_creation_time_subpacket.cpp
  openpgp/signature/subpacket/signature_expiration_time_subpacket.cpp
  openpgp/signature/subpacket/signature_target_subpacket.cpp
  openpgp/signature/subpacket/signers_user_id_subpacket.cpp
  openpgp/signature/subpacket/trust_signature_subpacket.cpp
  openpgp/symmetrically_encrypted_data_packet.cpp
  openpgp/symmetrically_encrypted_integrity_protected_data_packet.cpp
  openpgp/trust_packet.cpp
  openpgp/user_attribute/subpacket/image_attribute_subpacket.cpp
  openpgp/user_attribute/subpacket/raw_user_attribute_subpacket.cpp
  openpgp/user_attribute/user_attribute_subpacket.cpp
  openpgp/user_attribute_packet.cpp
  openpgp/user_id_packet.cpp
  parser/openpgp.cpp
  parser/parser_input.cpp
  proto/http.cpp
  proto/uri.cpp
  utils/stream.cpp
  utils/time.cpp
)
target_include_directories(neopg PUBLIC
  "${CMAKE_BINARY_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  ${PEGTL_INCLUDE_DIR}
  ${JSON_INCLUDE_DIR}
  ${Boost_INCLUDE_DIR}
  ${BOTAN2_INCLUDE_DIRS}
  ${CURL_INCLUDE_DIRS}
)

target_compile_options(neopg
  PRIVATE
  -fvisibility=hidden
  ${BOTAN2_CFLAGS_OTHER}
)

target_link_libraries(neopg PUBLIC
${BOTAN2_LDFLAGS} ${BOTAN2_LIBRARIES}
${CURL_LDFLAGS} ${CURL_LIBRARIES}
)

# Publish header files for libneopg
set(NeopgPublishedHeaders "")
set(NeopgPublishedHeadersDir "${CMAKE_BINARY_DIR}/include/neopg")

foreach(Header IN LISTS NeopgHeaders)
  get_filename_component(HeaderFilename "${Header}" NAME)
  set(Output "${NeopgPublishedHeadersDir}/${HeaderFilename}")
  list(APPEND NeopgPublishedHeaders "${Output}")
  add_custom_command(
    OUTPUT "${Output}"
    COMMAND "${CMAKE_COMMAND}" -E
      make_directory "${NeopgPublishedHeadersDir}"
    COMMAND "${CMAKE_COMMAND}" -E
      copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/${Header}" "${Output}"
    MAIN_DEPENDENCY "${Header}"
    COMMENT "Publishing ${HeaderFilename}"
    VERBATIM
  )
endforeach()
add_custom_target(
  neopg_headers
  DEPENDS ${NeopgPublishedHeaders}
  SOURCES ${NeopgHeaders}
)

add_dependencies(neopg neopg_headers)

add_subdirectory(tests)
