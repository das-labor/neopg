# NeoPG - tests
#   Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

FIND_PACKAGE(Boost COMPONENTS date_time REQUIRED)

# libneopg

set(LIBNEOPG_INCLUDE ../include)

add_library(libneopg
  ../include/neopg/openpgp/header.h
  ../include/neopg/openpgp/literal_data_packet.h
  ../include/neopg/openpgp/marker_packet.h
  ../include/neopg/openpgp/packet.h
  ../include/neopg/openpgp/user_id_packet.h
  ../include/neopg/openpgp/user_attribute_packet.h
  ../include/neopg/openpgp/modification_detection_code_packet.h
  ../include/neopg/openpgp/symmetrically_encrypted_integrity_protected_data_packet.h
  ../include/neopg/openpgp/symmetrically_encrypted_data_packet.h
  ../include/neopg/openpgp/compressed_data_packet.h
  ../include/neopg/openpgp/trust_packet.h
  ../include/neopg/parser/openpgp.h
  ../include/neopg/utils/time.h
  utils/time.cpp
  utils/stream.cpp
  openpgp/header.cpp
  openpgp/literal_data_packet.cpp
  openpgp/marker_packet.cpp
  openpgp/packet.cpp
  openpgp/user_id_packet.cpp
  openpgp/user_attribute_packet.cpp
  openpgp/modification_detection_code_packet.cpp
  openpgp/symmetrically_encrypted_integrity_protected_data_packet.cpp
  openpgp/symmetrically_encrypted_data_packet.cpp
  openpgp/compressed_data_packet.cpp
  openpgp/trust_packet.cpp
)

# On some systems, -U_GNU_SOURCE doesn't work (cmath tries to use ::isinf and fails).
target_compile_options(libneopg
  PRIVATE
  -fvisibility=hidden -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
  -std=c++11
)

target_include_directories(libneopg PUBLIC
   ${LIBNEOPG_INCLUDE}
   ${PEGTL_INCLUDE_DIR}
   ${GTEST_INCLUDE_DIR}
   ${Boost_INCLUDE_DIR}
)
