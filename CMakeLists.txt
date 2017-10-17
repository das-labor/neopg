cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(NeoPG VERSION 0.1 LANGUAGES C CXX)

# Google Test
set(GTEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/googletest)
set(GTEST_INCLUDE_DIR ${GTEST_ROOT}/include)
if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Windows")
  set(gtest_force_shared_crt ON CACHE BOOL
    "Use shared (DLL) run-time lib even when Google Test is built as static lib.")
endif()
add_subdirectory(${GTEST_ROOT} EXCLUDE_FROM_ALL)
add_library(GTest::GTest ALIAS gtest)
add_library(GTest::Main ALIAS gtest_main)

enable_testing()

# PEGTL
set(PEGTL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/pegtl)
set(PEGTL_INCLUDE_DIR ${PEGTL_ROOT}/include)
set(PEGTL_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory(${PEGTL_ROOT} EXCLUDE_FROM_ALL)
# taocpp:pegtl

# CodeCoverage

include(ProcessorCount)
ProcessorCount(PROCESSOR_COUNT)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(CodeCoverage)
APPEND_COVERAGE_COMPILER_FLAGS()

set(COVERAGE_EXCLUDES '*/3rdparty/*' '*/legacy/*' '*/usr/*' '*/nix/store/*')
SETUP_TARGET_FOR_COVERAGE(
     NAME coverage
     EXECUTABLE test-neopg
     DEPENDENCIES neopg
)
SETUP_TARGET_FOR_COVERAGE_COBERTURA(
     NAME coverage-data
     EXECUTABLE test-neopg
     DEPENDENCIES neopg
)


# Doxygen

find_package(Doxygen)
option(BUILD_DOC "Create and install documentation (requires Doxygen)" ${DOXYGEN_FOUND})

if(BUILD_DOC)
    if(NOT DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen is needed to build the documentation.")
    endif()

    set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/src/Doxyfile.in)
    set(DOXYFILE ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    configure_file(${DOXYFILE_IN} ${DOXYFILE} @ONLY)
    message("Doxygen build started")

    add_custom_target(doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating documentation with Doxygen"
        VERBATIM)

    # install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc)
endif()

find_package(Intl REQUIRED)
find_package(Iconv REQUIRED)

find_package(PkgConfig)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(BOTAN2 REQUIRED botan-2)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

include(CheckIncludeFiles)
check_include_files(malloc.h HAVE_MALLOC_H)

include (CheckFunctionExists)
check_function_exists (log HAVE_LOG)
check_function_exists (exp HAVE_EXP)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# libgpg-error

add_library(gpg-error
  legacy/libgpg-error/src/gpg-error.h
  legacy/libgpg-error/src/b64dec.cpp
  legacy/libgpg-error/src/code-from-errno.cpp
  legacy/libgpg-error/src/code-to-errno.cpp
  legacy/libgpg-error/src/strerror.cpp
  legacy/libgpg-error/src/estream.h
  legacy/libgpg-error/src/estream.cpp
  legacy/libgpg-error/src/estream-printf.cpp
  legacy/libgpg-error/src/gpg-error.h
  legacy/libgpg-error/src/gpgrt.h
  legacy/libgpg-error/src/gpgrt-int.h
  legacy/libgpg-error/src/init.h
  legacy/libgpg-error/src/init.cpp
  legacy/libgpg-error/src/visibility.h
  legacy/libgpg-error/src/visibility.cpp
  legacy/libgpg-error/src/gettext.h
)

if(WIN32)
  target_sources(gpg-error PRIVATE
    legacy/libgpg-error/src/w32-add.h
    legacy/libgpg-error/src/w32-estream.cpp
    legacy/libgpg-error/src/w32-gettext.cpp
    legacy/libgpg-error/src/w32-iconv.cpp
    legacy/libgpg-error/src/w32-lock.cpp
    legacy/libgpg-error/src/w32-thread.cpp
  )
else()
  target_sources(gpg-error PRIVATE
  legacy/libgpg-error/src/posix-lock.cpp
  legacy/libgpg-error/src/posix-thread.cpp
)
endif()

add_library(neopg::gpg-error ALIAS gpg-error)

target_include_directories(gpg-error PRIVATE
  legacy/libgpg-error/src
  ${Intl_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gpg-error PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(gpg-error PRIVATE pthread
  ${Intl_LDFLAGS} ${Intl_LIBRARIES})
target_compile_options(gpg-error PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_executable(gpg-error-test
  legacy/libgpg-error/tests/t-b64dec.cpp
  legacy/libgpg-error/tests/t-lock.cpp
  legacy/libgpg-error/tests/t-poll.cpp
  legacy/libgpg-error/tests/t-printf.cpp
  legacy/libgpg-error/tests/t-strerror.cpp
  legacy/libgpg-error/tests/t-syserror.cpp
  legacy/libgpg-error/tests/gpg-error-test.cpp
)
target_include_directories(gpg-error-test PRIVATE
  legacy/libgpg-error/src
  ${CMAKE_BINARY_DIR}/.)
target_link_libraries(gpg-error-test PRIVATE
  gpg-error
  GTest::GTest GTest::Main)
add_test(GpgErrorTest gpg-error-test COMMAND gpg-error-test test_xml_output --gtest_output=xml:gpg-error-test.xml)

# libassuan

add_library(assuan
  legacy/libassuan/src/assuan-buffer.cpp
  legacy/libassuan/src/assuan-defs.h
  legacy/libassuan/src/assuan-error.cpp
  legacy/libassuan/src/assuan-handler.cpp
  legacy/libassuan/src/assuan-inquire.cpp
  legacy/libassuan/src/assuan-io.cpp
  legacy/libassuan/src/assuan-listen.cpp
  legacy/libassuan/src/assuan-logging.cpp
  legacy/libassuan/src/assuan-pipe-connect.cpp
  legacy/libassuan/src/assuan-pipe-server.cpp
  legacy/libassuan/src/assuan-socket.cpp
  legacy/libassuan/src/assuan-uds.cpp
  legacy/libassuan/src/assuan.cpp
  legacy/libassuan/src/assuan.h
  legacy/libassuan/src/client.cpp
  legacy/libassuan/src/context.cpp
  legacy/libassuan/src/conversion.cpp
  legacy/libassuan/src/debug.cpp
  legacy/libassuan/src/debug.h
  legacy/libassuan/src/server.cpp
  legacy/libassuan/src/system.cpp
  legacy/libassuan/src/sysutils.cpp
)

if(WIN32)
  target_sources(assuan PRIVATE
    legacy/libassuan/src/system-w32.cpp
  )
else()
  target_sources(assuan PRIVATE
    legacy/libassuan/src/system-posix.cpp
)
endif()

target_compile_options(assuan PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_library(neopg::assuan ALIAS assuan)

target_include_directories(assuan PRIVATE
  legacy/libgpg-error/src
  legacy/libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(assuan PRIVATE gpg-error)

add_executable(assuan-test
  legacy/libassuan/tests/fdpassing.cpp
  legacy/libassuan/tests/assuan-test.cpp)
target_include_directories(assuan-test PRIVATE
  legacy/libgpg-error/src
  legacy/libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan-test PRIVATE
CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/legacy/libassuan/tests")
target_compile_options(assuan-test PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)
target_link_libraries(assuan-test PRIVATE
  assuan
  GTest::GTest GTest::Main)
add_test(AssuanTest assuan-test COMMAND assuan-test test_xml_output --gtest_output=xml:assuan-test.xml)

# npth

add_library(npth
  legacy/npth/src/npth.h
  legacy/npth/src/npth.cpp
  legacy/npth/src/npth-sigev.cpp
)
add_library(neopg::npth ALIAS npth)

target_include_directories(npth PRIVATE
  legacy/npth/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(npth PRIVATE
  HAVE_CONFIG_H=1)

target_compile_options(npth PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_executable(npth-test
  legacy/npth/tests/t-fork.cpp
  legacy/npth/tests/t-mutex.cpp
  legacy/npth/tests/t-support.h
  legacy/npth/tests/t-thread.cpp
  legacy/npth/tests/npth-test.cpp)
target_include_directories(npth-test PRIVATE
  legacy/npth/src
  ${CMAKE_BINARY_DIR}/.)
target_link_libraries(npth-test PRIVATE
  npth
  GTest::GTest GTest::Main)
add_test(nPthTest npth-test COMMAND npth-test test_xml_output --gtest_output=xml:npth-test.xml)

# libgcrypt

add_library(gcrypt
  legacy/libgcrypt/src/cipher-proto.h
  legacy/libgcrypt/src/cipher.h
  legacy/libgcrypt/src/context.cpp
  legacy/libgcrypt/src/context.h
  legacy/libgcrypt/src/ec-context.h
  legacy/libgcrypt/src/fips.cpp
  legacy/libgcrypt/src/g10lib.h
  legacy/libgcrypt/src/gcrypt-int.h
  legacy/libgcrypt/src/gcrypt-testapi.h
  legacy/libgcrypt/src/gcrypt.h
  legacy/libgcrypt/src/global.cpp
  legacy/libgcrypt/src/hmac256.cpp
  legacy/libgcrypt/src/hmac256.h
  legacy/libgcrypt/src/hwf-common.h
  legacy/libgcrypt/src/hwf-x86.cpp
  legacy/libgcrypt/src/hwfeatures.cpp
  legacy/libgcrypt/src/misc.cpp
  legacy/libgcrypt/src/mpi.h
  legacy/libgcrypt/src/secmem.cpp
  legacy/libgcrypt/src/secmem.h
  legacy/libgcrypt/src/sexp.cpp
  legacy/libgcrypt/src/stdmem.cpp
  legacy/libgcrypt/src/stdmem.h
  legacy/libgcrypt/src/types.h
  legacy/libgcrypt/src/visibility.cpp
  legacy/libgcrypt/src/visibility.h
  legacy/libgcrypt/cipher/crc.cpp
  legacy/libgcrypt/cipher/ecc.cpp
  legacy/libgcrypt/cipher/ecc-curves.cpp
  legacy/libgcrypt/cipher/ecc-eddsa.cpp
  legacy/libgcrypt/cipher/ecc-gost.cpp
  legacy/libgcrypt/cipher/ecc-misc.cpp
  legacy/libgcrypt/cipher/ecc-ecdsa.cpp
  legacy/libgcrypt/cipher/elgamal.cpp
  legacy/libgcrypt/cipher/des.cpp
  legacy/libgcrypt/cipher/dsa.cpp
  legacy/libgcrypt/cipher/rsa.cpp
  legacy/libgcrypt/cipher/sha1.cpp
  legacy/libgcrypt/cipher/sha256.cpp
  legacy/libgcrypt/cipher/sha512.cpp
  legacy/libgcrypt/cipher/keccak.cpp
  legacy/libgcrypt/cipher/whirlpool.cpp
  legacy/libgcrypt/cipher/md4.cpp
  legacy/libgcrypt/cipher/md5.cpp
  legacy/libgcrypt/cipher/rmd160.cpp
  legacy/libgcrypt/cipher/blowfish.cpp
  legacy/libgcrypt/cipher/camellia.cpp
  legacy/libgcrypt/cipher/camellia-glue.cpp
  legacy/libgcrypt/cipher/rijndael.cpp
  legacy/libgcrypt/cipher/idea.cpp
  legacy/libgcrypt/cipher/cast5.cpp
  legacy/libgcrypt/cipher/twofish.cpp
  legacy/libgcrypt/cipher/rfc2268.cpp
  legacy/libgcrypt/cipher/seed.cpp
  legacy/libgcrypt/cipher/mac-cmac.cpp
  legacy/libgcrypt/cipher/serpent.cpp
  legacy/libgcrypt/cipher/cipher.cpp
  legacy/libgcrypt/cipher/cipher-internal.h
  legacy/libgcrypt/cipher/cipher-cbc.cpp
  legacy/libgcrypt/cipher/cipher-cfb.cpp
  legacy/libgcrypt/cipher/cipher-ofb.cpp
  legacy/libgcrypt/cipher/cipher-ctr.cpp
  legacy/libgcrypt/cipher/cipher-aeswrap.cpp
  legacy/libgcrypt/cipher/cipher-ccm.cpp
  legacy/libgcrypt/cipher/cipher-cmac.cpp
  legacy/libgcrypt/cipher/cipher-gcm.cpp
  legacy/libgcrypt/cipher/cipher-poly1305.cpp
  legacy/libgcrypt/cipher/cipher-ocb.cpp
  legacy/libgcrypt/cipher/cipher-xts.cpp
  legacy/libgcrypt/cipher/cipher-selftest.cpp
  legacy/libgcrypt/cipher/cipher-selftest.h
  legacy/libgcrypt/cipher/pubkey.cpp
  legacy/libgcrypt/cipher/pubkey-internal.h
  legacy/libgcrypt/cipher/pubkey-util.cpp
  legacy/libgcrypt/cipher/md.cpp
  legacy/libgcrypt/cipher/mac.cpp
  legacy/libgcrypt/cipher/mac-internal.h
  legacy/libgcrypt/cipher/mac-hmac.cpp
  legacy/libgcrypt/cipher/mac-cmac.cpp
  legacy/libgcrypt/cipher/mac-gmac.cpp
  legacy/libgcrypt/cipher/mac-poly1305.cpp
  legacy/libgcrypt/cipher/poly1305.cpp
  legacy/libgcrypt/cipher/poly1305-internal.h
  legacy/libgcrypt/cipher/kdf.cpp
  legacy/libgcrypt/cipher/scrypt.cpp
  legacy/libgcrypt/cipher/kdf-internal.h
  legacy/libgcrypt/cipher/bithelp.h
  legacy/libgcrypt/cipher/bufhelp.h
  legacy/libgcrypt/cipher/primegen.cpp
  legacy/libgcrypt/cipher/hash-common.cpp
  legacy/libgcrypt/cipher/hash-common.h
  legacy/libgcrypt/cipher/dsa-common.cpp
  legacy/libgcrypt/cipher/rsa-common.cpp
  legacy/libgcrypt/cipher/sha1.h
  legacy/libgcrypt/mpi/ec.cpp
  legacy/libgcrypt/mpi/mpi-add.cpp
  legacy/libgcrypt/mpi/mpi-bit.cpp
  legacy/libgcrypt/mpi/mpi-cmp.cpp
  legacy/libgcrypt/mpi/mpicoder.cpp
  legacy/libgcrypt/mpi/mpi-div.cpp
  legacy/libgcrypt/mpi/mpi-gcd.cpp
  legacy/libgcrypt/mpi/mpih-div.cpp
  legacy/libgcrypt/mpi/mpih-mul.cpp
  legacy/libgcrypt/mpi/mpi-inline.cpp
  legacy/libgcrypt/mpi/mpi-inv.cpp
  legacy/libgcrypt/mpi/mpi-mod.cpp
  legacy/libgcrypt/mpi/mpi-mpow.cpp
  legacy/libgcrypt/mpi/mpi-mul.cpp
  legacy/libgcrypt/mpi/mpi-pow.cpp
  legacy/libgcrypt/mpi/mpi-scan.cpp
  legacy/libgcrypt/mpi/mpiutil.cpp
  legacy/libgcrypt/mpi/mpih-add1.cpp
  legacy/libgcrypt/mpi/generic/mpih-lshift.cpp
  legacy/libgcrypt/mpi/generic/mpih-mul1.cpp
  legacy/libgcrypt/mpi/generic/mpih-mul2.cpp
  legacy/libgcrypt/mpi/generic/mpih-mul3.cpp
  legacy/libgcrypt/mpi/generic/mpih-rshift.cpp
  legacy/libgcrypt/mpi/generic/mpih-sub1.cpp
  legacy/libgcrypt/mpi/generic/udiv-w-sdiv.cpp
  legacy/libgcrypt/random/rand-internal.h
  legacy/libgcrypt/random/random.cpp
  legacy/libgcrypt/random/random-csprng.cpp
  legacy/libgcrypt/random/random-drbg.cpp
  legacy/libgcrypt/random/random-fips.cpp
  legacy/libgcrypt/random/random.h
  legacy/libgcrypt/random/random-system.cpp
  legacy/libgcrypt/random/rndhw.cpp
  legacy/libgcrypt/random/rndlinux.cpp
)
add_library(neopg::gcrypt ALIAS gcrypt)

target_include_directories(gcrypt PRIVATE
  legacy/libgpg-error/src
  legacy/libgcrypt/mpi
  legacy/libgcrypt/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gcrypt PRIVATE
  HAVE_CONFIG_H=1)

target_compile_options(gcrypt PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_executable(gcrypt-test
  legacy/libgcrypt/tests/hmac.cpp
  legacy/libgcrypt/tests/gcrypt-test.cpp)
target_include_directories(gcrypt-test PRIVATE
  legacy/libgpg-error/src
  legacy/libgcrypt/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_options(gcrypt-test PUBLIC -fpermissive -Wnarrowing -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)
target_link_libraries(gcrypt-test PRIVATE
  gcrypt
  gpg-error
  GTest::GTest GTest::Main)
add_test(GcryptTest gcrypt-test COMMAND gcrypt-test test_xml_output --gtest_output=xml:gcrypt-test.xml)

add_executable(gcrypt-secmem-test
  legacy/libgcrypt/tests/t-secmem.cpp
  legacy/libgcrypt/tests/gcrypt-secmem-test.cpp)
target_include_directories(gcrypt-secmem-test PRIVATE
    legacy/libgpg-error/src
    legacy/libgcrypt/src
    ${CMAKE_BINARY_DIR}/.)
target_compile_options(gcrypt-secmem-test PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)
  target_link_libraries(gcrypt-secmem-test PRIVATE
    gcrypt
    gpg-error
    GTest::GTest GTest::Main)
  add_test(GcryptSecmemTest gcrypt-secmem-test COMMAND gcrypt-secmem-test test_xml_output --gtest_output=xml:gcrypt-secmem-test.xml)

# libksba

add_library(ksba
  legacy/libksba/src/ksba.h
  legacy/libksba/src/visibility.cpp
  legacy/libksba/src/reader.cpp
  legacy/libksba/src/writer.cpp
  legacy/libksba/src/asn1-parse.cpp
  legacy/libksba/src/asn1-func.cpp
  legacy/libksba/src/asn1-func2.cpp
  legacy/libksba/src/ber-help.cpp
  legacy/libksba/src/ber-decoder.cpp
  legacy/libksba/src/der-encoder.cpp
  legacy/libksba/src/cert.cpp
  legacy/libksba/src/cms.cpp
  legacy/libksba/src/cms-parser.cpp
  legacy/libksba/src/crl.cpp
  legacy/libksba/src/certreq.cpp
  legacy/libksba/src/ocsp.cpp
  legacy/libksba/src/keyinfo.cpp
  legacy/libksba/src/oid.cpp
  legacy/libksba/src/name.cpp
  legacy/libksba/src/dn.cpp
  legacy/libksba/src/time.cpp
  legacy/libksba/src/util.cpp
  legacy/libksba/src/asn1-tables.cpp
)
add_library(neopg::ksba ALIAS ksba)

target_include_directories(ksba PRIVATE
  legacy/libgpg-error/src
  legacy/libksba/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(ksba PRIVATE
  HAVE_CONFIG_H=1)

target_compile_options(ksba PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_executable(ksba-test
  legacy/libksba/tests/ksba-test.cpp
  legacy/libksba/tests/t-oid.cpp
  legacy/libksba/tests/t-crl-parser.cpp
  legacy/libksba/tests/t-dnparser.cpp
  )
target_include_directories(ksba-test PRIVATE
  legacy/libgpg-error/src
  legacy/libksba/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(ksba-test PRIVATE
  CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/legacy/libksba/tests")
target_link_libraries(ksba-test PRIVATE
  gpg-error
  ksba
  GTest::GTest GTest::Main)
add_test(KsbaTest ksba-test COMMAND ksba-test test_xml_output --gtest_output=xml:ksba-test.xml)


FIND_PACKAGE(Boost COMPONENTS date_time REQUIRED)

# libneopg

set(LIBNEOPG_INCLUDE include)

add_library(libneopg
  include/neopg/openpgp/header.h
  include/neopg/openpgp/marker_packet.h
  include/neopg/openpgp/packet.h
  include/neopg/utils/time.h
  src/lib/utils/time.cpp
  src/openpgp/header.cpp
  src/openpgp/marker_packet.cpp
  src/openpgp/packet.cpp
)
target_compile_options(libneopg
  PRIVATE
  -fvisibility=hidden -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
  -std=c++14
)
target_include_directories(libneopg PUBLIC
   ${LIBNEOPG_INCLUDE}
   ${PEGTL_INCLUDE_DIR})
target_compile_definitions(gpg-error
   PRIVATE
)



add_executable(neopg
  legacy/gnupg/common/logging.h
  legacy/gnupg/common/logging.cpp
  legacy/gnupg/common/sysutils.h
  legacy/gnupg/common/sysutils.cpp
  legacy/gnupg/common/utf8conv.h
  legacy/gnupg/common/utf8conv.cpp
  legacy/gnupg/common/stringhelp.h
  legacy/gnupg/common/stringhelp.cpp
  legacy/gnupg/common/server-help.h
  legacy/gnupg/common/server-help.cpp
  legacy/gnupg/common/argparse.h
  legacy/gnupg/common/argparse.cpp
  legacy/gnupg/common/strlist.h
  legacy/gnupg/common/strlist.cpp
  legacy/gnupg/common/membuf.h
  legacy/gnupg/common/membuf.cpp
  legacy/gnupg/common/status.h
  legacy/gnupg/common/status.cpp
  legacy/gnupg/common/iobuf.h
  legacy/gnupg/common/iobuf.cpp
  legacy/gnupg/common/i18n.h
  legacy/gnupg/common/i18n.cpp
  legacy/gnupg/common/gettime.h
  legacy/gnupg/common/gettime.cpp
  legacy/gnupg/common/asshelp.h
  legacy/gnupg/common/asshelp.cpp
  legacy/gnupg/common/dotlock.h
  legacy/gnupg/common/dotlock.cpp
  legacy/gnupg/common/mischelp.h
  legacy/gnupg/common/compliance.h
  legacy/gnupg/common/compliance.cpp
  legacy/gnupg/common/exechelp.h
  legacy/gnupg/common/exechelp-posix.cpp
  legacy/gnupg/common/userids.h
  legacy/gnupg/common/userids.cpp
  legacy/gnupg/common/mbox-util.h
  legacy/gnupg/common/mbox-util.cpp
  legacy/gnupg/common/recsel.h
  legacy/gnupg/common/recsel.cpp
  legacy/gnupg/common/gpgrlhelp.cpp
  legacy/gnupg/common/homedir.cpp
  legacy/gnupg/common/miscellaneous.cpp
  legacy/gnupg/common/init.cpp
  legacy/gnupg/common/percent.cpp
  legacy/gnupg/common/zb32.cpp
  legacy/gnupg/common/openpgp-oid.cpp
  legacy/gnupg/common/ttyio.cpp
  legacy/gnupg/common/xasprintf.cpp
  legacy/gnupg/common/yesno.cpp
  legacy/gnupg/common/sexputil.cpp
  legacy/gnupg/common/tlv.cpp
  legacy/gnupg/common/util.h
  legacy/gnupg/common/localename.cpp
  legacy/gnupg/common/convert.cpp
  legacy/gnupg/common/b64enc.cpp
  legacy/gnupg/kbx/keybox-init.cpp
  legacy/gnupg/kbx/keybox-util.cpp
  legacy/gnupg/kbx/keybox-blob.cpp
  legacy/gnupg/kbx/keybox-file.cpp
  legacy/gnupg/kbx/keybox-openpgp.cpp
  legacy/gnupg/kbx/keybox-update.cpp
  legacy/gnupg/kbx/keybox-search.cpp
  legacy/gnupg/g10/misc.cpp
  legacy/gnupg/g10/keyid.cpp
  legacy/gnupg/g10/keyserver.cpp
  legacy/gnupg/g10/pubkey-enc.cpp
  legacy/gnupg/g10/pkclist.cpp
  legacy/gnupg/g10/ecdh.cpp
  legacy/gnupg/g10/kbnode.cpp
  legacy/gnupg/g10/compress.cpp
  legacy/gnupg/g10/filter.h
  legacy/gnupg/g10/passphrase.cpp
  legacy/gnupg/g10/import.cpp
  legacy/gnupg/g10/export.cpp
  legacy/gnupg/g10/decrypt-data.cpp
  legacy/gnupg/g10/plaintext.cpp
  legacy/gnupg/g10/textfilter.cpp
  legacy/gnupg/g10/progress.cpp
  legacy/gnupg/g10/mdfilter.cpp
  legacy/gnupg/g10/seskey.cpp
  legacy/gnupg/g10/pkglue.cpp
  legacy/gnupg/g10/revoke.cpp
  legacy/gnupg/g10/sign.cpp
  legacy/gnupg/g10/encrypt.cpp
  legacy/gnupg/g10/decrypt.cpp
  legacy/gnupg/g10/cipher.cpp
  legacy/gnupg/g10/verify.cpp
  legacy/gnupg/g10/skclist.cpp
  legacy/gnupg/g10/keygen.cpp
  legacy/gnupg/g10/call-dirmngr.cpp
  legacy/gnupg/g10/call-agent.cpp
  legacy/gnupg/g10/getkey.cpp
  legacy/gnupg/g10/keydb.cpp
  legacy/gnupg/g10/packet.h
  legacy/gnupg/g10/build-packet.cpp
  legacy/gnupg/g10/parse-packet.cpp
  legacy/gnupg/g10/mainproc.cpp
  legacy/gnupg/g10/free-packet.cpp
  legacy/gnupg/g10/sig-check.cpp
  legacy/gnupg/g10/keyedit.cpp
  legacy/gnupg/g10/trust.cpp
  legacy/gnupg/g10/cpr.cpp
  legacy/gnupg/g10/keylist.cpp
  legacy/gnupg/g10/openfile.cpp
  legacy/gnupg/g10/key-check.cpp
  legacy/gnupg/g10/armor.cpp
  legacy/gnupg/g10/trustdb.cpp
  legacy/gnupg/g10/tdbio.cpp
  legacy/gnupg/g10/tdbdump.cpp
  legacy/gnupg/g10/exec.cpp
  legacy/gnupg/g10/delkey.cpp
  legacy/gnupg/g10/dearmor.cpp
  legacy/gnupg/g10/tofu.cpp
  legacy/gnupg/g10/card-util.cpp
  legacy/gnupg/g10/gpgsql.cpp
  legacy/gnupg/g10/compress-bz2.cpp
  legacy/gnupg/g10/gpg.cpp

  legacy/gnupg/agent/command.cpp
  legacy/gnupg/agent/gpg-agent.cpp
  legacy/gnupg/agent/protect.cpp
  legacy/gnupg/agent/call-scd.cpp
  legacy/gnupg/agent/findkey.cpp
  legacy/gnupg/agent/cvt-openpgp.cpp
  legacy/gnupg/agent/cache.cpp
  legacy/gnupg/agent/genkey.cpp
  legacy/gnupg/agent/call-pinentry.cpp
  legacy/gnupg/agent/trustlist.cpp
  legacy/gnupg/common/asshelp2.cpp
  legacy/gnupg/common/asshelp.h
  legacy/gnupg/agent/pkdecrypt.cpp
  legacy/gnupg/agent/pksign.cpp
  legacy/gnupg/agent/learncard.cpp
  legacy/gnupg/agent/divert-scd.cpp
  legacy/gnupg/common/name-value.cpp

  legacy/gnupg/dirmngr/dirmngr.cpp
  legacy/gnupg/dirmngr/crlfetch.cpp
  legacy/gnupg/dirmngr/dirmngr-client.cpp
  legacy/gnupg/dirmngr/dirmngr.cpp
  legacy/gnupg/dirmngr/dns-stuff.cpp
  legacy/gnupg/dirmngr/http-common.cpp
  legacy/gnupg/dirmngr/http.cpp
  legacy/gnupg/dirmngr/ks-action.cpp
  legacy/gnupg/dirmngr/ks-engine-hkp.cpp
  legacy/gnupg/dirmngr/ks-engine-http.cpp
  legacy/gnupg/dirmngr/ks-engine-kdns.cpp
  legacy/gnupg/dirmngr/misc.cpp
  legacy/gnupg/dirmngr/ocsp.cpp
  legacy/gnupg/dirmngr/server.cpp
  legacy/gnupg/dirmngr/validate.cpp
  legacy/gnupg/dirmngr/crlcache.cpp
  legacy/gnupg/dirmngr/certcache.cpp
  legacy/gnupg/dirmngr/cdblib.cpp
  legacy/gnupg/common/ksba-io-support.cpp
  legacy/gnupg/common/exectool.cpp

  legacy/gnupg/sm/call-agent.cpp
  legacy/gnupg/sm/certcheck.cpp
  legacy/gnupg/sm/certreqgen.cpp
  legacy/gnupg/sm/delete.cpp
  legacy/gnupg/sm/fingerprint.cpp
  legacy/gnupg/sm/sign.cpp
  legacy/gnupg/sm/call-dirmngr.cpp
  legacy/gnupg/sm/certdump.cpp
  legacy/gnupg/sm/certreqgen-ui.cpp
  legacy/gnupg/sm/encrypt.cpp
  legacy/gnupg/sm/gpgsm.cpp
  legacy/gnupg/sm/import.cpp
  legacy/gnupg/sm/keylist.cpp
  legacy/gnupg/sm/misc.cpp
  legacy/gnupg/sm/verify.cpp
  legacy/gnupg/sm/certchain.cpp
  legacy/gnupg/sm/certlist.cpp
  legacy/gnupg/sm/decrypt.cpp
  legacy/gnupg/sm/export.cpp
  legacy/gnupg/sm/keydb.cpp
  legacy/gnupg/sm/minip12.cpp
  legacy/gnupg/sm/passphrase.cpp
  legacy/gnupg/sm/server.cpp
  legacy/gnupg/sm/gpgsm.cpp

  legacy/gnupg/scd/scdaemon.cpp
  legacy/gnupg/scd/apdu.cpp
  legacy/gnupg/scd/app.cpp
  legacy/gnupg/scd/app-dinsig.cpp
  legacy/gnupg/scd/app-help.cpp
  legacy/gnupg/scd/app-nks.cpp
  legacy/gnupg/scd/app-p15.cpp
  legacy/gnupg/scd/app-sc-hsm.cpp
  legacy/gnupg/scd/app-openpgp.cpp
  legacy/gnupg/scd/atr.cpp
  legacy/gnupg/scd/ccid-driver.cpp
  legacy/gnupg/scd/command.cpp
  legacy/gnupg/scd/iso7816.cpp

  src/neopg.cpp
)
target_include_directories(neopg PRIVATE
  legacy/libgpg-error/src
  legacy/libassuan/src
  legacy/libgcrypt/src
  legacy/npth/src
  legacy/libksba/src
  ${CMAKE_BINARY_DIR}/.
  ${Boost_INCLUDE_DIR}
  ${SQLITE3_INCLUDE_DIRS}
  ${BOTAN2_INCLUDE_DIRS}
  ${LIBUSB_INCLUDE_DIRS}
  ${ICONV_INCLUDE_DIRS}
  src/lib
)
target_compile_definitions(neopg PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(neopg PRIVATE
  gpg-error
  assuan
  gcrypt
  npth
  ksba
# ${Boost_LIBRARIES}
${SQLITE3_LDFLAGS} ${SQLITE3_LIBRARIES}
${BOTAN2_LDFLAGS} ${BOTAN2_LIBRARIES}
${LIBUSB_LDFLAGS} ${LIBUSB_LIBRARIES}
${ICONV_LDFLAGS} ${ICONV_LIBRARIES}
 -lresolv -lz -lbz2 -lgnutls
 libneopg
)
target_compile_options(neopg PUBLIC
 -fpermissive
  -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
-std=c++14
${SQLITE3_CFLAGS_OTHER}
${BOTAN2_CFLAGS_OTHER})

add_executable(test-neopg
  src/tests/openpgp.cpp
  )
target_compile_options(test-neopg
  PRIVATE
  -fvisibility=hidden -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
  -std=c++14
)
target_include_directories(test-neopg PRIVATE
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(test-neopg PRIVATE
  CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/src/tests")
target_link_libraries(test-neopg PRIVATE
  libneopg
  GTest::GTest GTest::Main)
add_test(NeoPGTest test-neopg COMMAND test-neopg test_xml_output --gtest_output=xml:test-neopg.xml)

# get all project files
file(GLOB_RECURSE ALL_SOURCE_FILES ${CMAKE_SOURCE_DIR}/src/*.cpp ${CMAKE_SOURCE_DIR}/src/*.h ${CMAKE_SOURCE_DIR}/include/*.cpp ${CMAKE_SOURCE_DIR}/include/*.h )

# additional target to perform cppcheck run, requires cppcheck

add_custom_target(
  lint
  COMMAND cppcheck
  --enable=warning,performance,portability,information,missingInclude
  --std=c++11
  --language=c++
  --verbose
  --quiet
  ${ALL_SOURCE_FILES}
)

# additional target to perform clang-format run, requires clang-format


add_custom_target(
  pretty
  COMMAND clang-format
  -style=Google
  -i
  ${ALL_SOURCE_FILES}
)


#if(CMAKE_COMPILER_IS_GNUCXX)
#  target_compile_options(foo
#  PUBLIC -fno-...)
#endif()
#target_compile_features(foo
#PUBLIC cxx_auto_type
#PRIVATE
#cxx_variadic_templates)
