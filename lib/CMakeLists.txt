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
  ../include/neopg/parser/openpgp.h
  ../include/neopg/utils/time.h
  utils/time.cpp
  utils/stream.cpp
  openpgp/header.cpp
  openpgp/literal_data_packet.cpp
  openpgp/marker_packet.cpp
  openpgp/packet.cpp
  openpgp/user_id_packet.cpp
)

target_compile_options(libneopg
  PRIVATE
  -fvisibility=hidden -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
  -std=c++14
)

target_include_directories(libneopg PUBLIC
   ${LIBNEOPG_INCLUDE}
   ${PEGTL_INCLUDE_DIR}
   ${GTEST_INCLUDE_DIR}
   ${Boost_INCLUDE_DIR}
)
