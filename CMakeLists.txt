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

set(COVERAGE_EXCLUDES '*/3rdparty/*' '*/nix/store/*')
SETUP_TARGET_FOR_COVERAGE(
     NAME coverage
     EXECUTABLE ctest -j ${PROCESSOR_COUNT}
     DEPENDENCIES neopg
)
SETUP_TARGET_FOR_COVERAGE_COBERTURA(
     NAME coverage-xml
     EXECUTABLE ctest -j ${PROCESSOR_COUNT}
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
  libgpg-error/src/gpg-error.h
  libgpg-error/src/b64dec.cpp
  libgpg-error/src/code-from-errno.cpp
  libgpg-error/src/code-to-errno.cpp
  libgpg-error/src/strerror.cpp
  libgpg-error/src/estream.h
  libgpg-error/src/estream.cpp
  libgpg-error/src/estream-printf.cpp
  libgpg-error/src/gpg-error.h
  libgpg-error/src/gpgrt.h
  libgpg-error/src/gpgrt-int.h
  libgpg-error/src/init.h
  libgpg-error/src/init.cpp
  libgpg-error/src/visibility.h
  libgpg-error/src/visibility.cpp
  libgpg-error/src/gettext.h
)

if(WIN32)
  target_sources(gpg-error PRIVATE
    libgpg-error/src/w32-add.h
    libgpg-error/src/w32-estream.cpp
    libgpg-error/src/w32-gettext.cpp
    libgpg-error/src/w32-iconv.cpp
    libgpg-error/src/w32-lock.cpp
    libgpg-error/src/w32-thread.cpp
  )
else()
  target_sources(gpg-error PRIVATE
  libgpg-error/src/posix-lock.cpp
  libgpg-error/src/posix-thread.cpp
)
endif()

add_library(neopg::gpg-error ALIAS gpg-error)

target_include_directories(gpg-error PRIVATE
  libgpg-error/src
  ${Intl_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gpg-error PRIVATE
  ${Intl_LDFLAGS} ${Intl_LIBRARIES}
  HAVE_CONFIG_H=1)
target_link_libraries(gpg-error PRIVATE pthread)
target_compile_options(gpg-error PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_executable(gpg-error-test
  libgpg-error/tests/t-b64dec.cpp
  libgpg-error/tests/t-lock.cpp
  libgpg-error/tests/t-poll.cpp
  libgpg-error/tests/t-printf.cpp
  libgpg-error/tests/t-strerror.cpp
  libgpg-error/tests/t-syserror.cpp
  libgpg-error/tests/gpg-error-test.cpp
)
target_include_directories(gpg-error-test PRIVATE
  libgpg-error/src
  ${CMAKE_BINARY_DIR}/.)
target_link_libraries(gpg-error-test PRIVATE
  gpg-error
  GTest::GTest GTest::Main)
add_test(GpgErrorTest gpg-error-test COMMAND gpg-error-test test_xml_output --gtest_output=xml:gpg-error-test.xml)

# libassuan

add_library(assuan
  libassuan/src/assuan-buffer.cpp
  libassuan/src/assuan-defs.h
  libassuan/src/assuan-error.cpp
  libassuan/src/assuan-handler.cpp
  libassuan/src/assuan-inquire.cpp
  libassuan/src/assuan-io.cpp
  libassuan/src/assuan-listen.cpp
  libassuan/src/assuan-logging.cpp
  libassuan/src/assuan-pipe-connect.cpp
  libassuan/src/assuan-pipe-server.cpp
  libassuan/src/assuan-socket.cpp
  libassuan/src/assuan-uds.cpp
  libassuan/src/assuan.cpp
  libassuan/src/assuan.h
  libassuan/src/client.cpp
  libassuan/src/context.cpp
  libassuan/src/conversion.cpp
  libassuan/src/debug.cpp
  libassuan/src/debug.h
  libassuan/src/server.cpp
  libassuan/src/system.cpp
  libassuan/src/sysutils.cpp
)

if(WIN32)
  target_sources(assuan PRIVATE
    libassuan/src/system-w32.cpp
  )
else()
  target_sources(assuan PRIVATE
    libassuan/src/system-posix.cpp
)
endif()

target_compile_options(assuan PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_library(neopg::assuan ALIAS assuan)

target_include_directories(assuan PRIVATE
  libgpg-error/src
  libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(assuan PRIVATE gpg-error)

add_executable(assuan-test
  libassuan/tests/fdpassing.cpp
  libassuan/tests/assuan-test.cpp)
target_include_directories(assuan-test PRIVATE
  libgpg-error/src
  libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan-test PRIVATE
CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/libassuan/tests")
target_compile_options(assuan-test PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)
target_link_libraries(assuan-test PRIVATE
  assuan
  GTest::GTest GTest::Main)
add_test(AssuanTest assuan-test COMMAND assuan-test test_xml_output --gtest_output=xml:assuan-test.xml)

# npth

add_library(npth
  npth/src/npth.h
  npth/src/npth.cpp
  npth/src/npth-sigev.cpp
)
add_library(neopg::npth ALIAS npth)

target_include_directories(npth PRIVATE
  npth/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(npth PRIVATE
  HAVE_CONFIG_H=1)

target_compile_options(npth PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_executable(npth-test
  npth/tests/t-fork.cpp
  npth/tests/t-mutex.cpp
  npth/tests/t-support.h
  npth/tests/t-thread.cpp
  npth/tests/npth-test.cpp)
target_include_directories(npth-test PRIVATE
  npth/src
  ${CMAKE_BINARY_DIR}/.)
target_link_libraries(npth-test PRIVATE
  npth
  GTest::GTest GTest::Main)
add_test(nPthTest npth-test COMMAND npth-test test_xml_output --gtest_output=xml:npth-test.xml)

# libgcrypt

add_library(gcrypt
  libgcrypt/src/cipher-proto.h
  libgcrypt/src/cipher.h
  libgcrypt/src/context.cpp
  libgcrypt/src/context.h
  libgcrypt/src/ec-context.h
  libgcrypt/src/fips.cpp
  libgcrypt/src/g10lib.h
  libgcrypt/src/gcrypt-int.h
  libgcrypt/src/gcrypt-testapi.h
  libgcrypt/src/gcrypt.h
  libgcrypt/src/global.cpp
  libgcrypt/src/hmac256.cpp
  libgcrypt/src/hmac256.h
  libgcrypt/src/hwf-common.h
  libgcrypt/src/hwf-x86.cpp
  libgcrypt/src/hwfeatures.cpp
  libgcrypt/src/misc.cpp
  libgcrypt/src/mpi.h
  libgcrypt/src/secmem.cpp
  libgcrypt/src/secmem.h
  libgcrypt/src/sexp.cpp
  libgcrypt/src/stdmem.cpp
  libgcrypt/src/stdmem.h
  libgcrypt/src/types.h
  libgcrypt/src/visibility.cpp
  libgcrypt/src/visibility.h
  libgcrypt/cipher/crc.cpp
  libgcrypt/cipher/ecc.cpp
  libgcrypt/cipher/ecc-curves.cpp
  libgcrypt/cipher/ecc-eddsa.cpp
  libgcrypt/cipher/ecc-gost.cpp
  libgcrypt/cipher/ecc-misc.cpp
  libgcrypt/cipher/ecc-ecdsa.cpp
  libgcrypt/cipher/elgamal.cpp
  libgcrypt/cipher/des.cpp
  libgcrypt/cipher/dsa.cpp
  libgcrypt/cipher/rsa.cpp
  libgcrypt/cipher/sha1.cpp
  libgcrypt/cipher/sha256.cpp
  libgcrypt/cipher/sha512.cpp
  libgcrypt/cipher/keccak.cpp
  libgcrypt/cipher/whirlpool.cpp
  libgcrypt/cipher/md4.cpp
  libgcrypt/cipher/md5.cpp
  libgcrypt/cipher/rmd160.cpp
  libgcrypt/cipher/blowfish.cpp
  libgcrypt/cipher/camellia.cpp
  libgcrypt/cipher/camellia-glue.cpp
  libgcrypt/cipher/rijndael.cpp
  libgcrypt/cipher/idea.cpp
  libgcrypt/cipher/cast5.cpp
  libgcrypt/cipher/twofish.cpp
  libgcrypt/cipher/rfc2268.cpp
  libgcrypt/cipher/seed.cpp
  libgcrypt/cipher/mac-cmac.cpp
  libgcrypt/cipher/serpent.cpp
  libgcrypt/cipher/cipher.cpp
  libgcrypt/cipher/cipher-internal.h
  libgcrypt/cipher/cipher-cbc.cpp
  libgcrypt/cipher/cipher-cfb.cpp
  libgcrypt/cipher/cipher-ofb.cpp
  libgcrypt/cipher/cipher-ctr.cpp
  libgcrypt/cipher/cipher-aeswrap.cpp
  libgcrypt/cipher/cipher-ccm.cpp
  libgcrypt/cipher/cipher-cmac.cpp
  libgcrypt/cipher/cipher-gcm.cpp
  libgcrypt/cipher/cipher-poly1305.cpp
  libgcrypt/cipher/cipher-ocb.cpp
  libgcrypt/cipher/cipher-xts.cpp
  libgcrypt/cipher/cipher-selftest.cpp
  libgcrypt/cipher/cipher-selftest.h
  libgcrypt/cipher/pubkey.cpp
  libgcrypt/cipher/pubkey-internal.h
  libgcrypt/cipher/pubkey-util.cpp
  libgcrypt/cipher/md.cpp
  libgcrypt/cipher/mac.cpp
  libgcrypt/cipher/mac-internal.h
  libgcrypt/cipher/mac-hmac.cpp
  libgcrypt/cipher/mac-cmac.cpp
  libgcrypt/cipher/mac-gmac.cpp
  libgcrypt/cipher/mac-poly1305.cpp
  libgcrypt/cipher/poly1305.cpp
  libgcrypt/cipher/poly1305-internal.h
  libgcrypt/cipher/kdf.cpp
  libgcrypt/cipher/scrypt.cpp
  libgcrypt/cipher/kdf-internal.h
  libgcrypt/cipher/bithelp.h
  libgcrypt/cipher/bufhelp.h
  libgcrypt/cipher/primegen.cpp
  libgcrypt/cipher/hash-common.cpp
  libgcrypt/cipher/hash-common.h
  libgcrypt/cipher/dsa-common.cpp
  libgcrypt/cipher/rsa-common.cpp
  libgcrypt/cipher/sha1.h
  libgcrypt/mpi/ec.cpp
  libgcrypt/mpi/mpi-add.cpp
  libgcrypt/mpi/mpi-bit.cpp
  libgcrypt/mpi/mpi-cmp.cpp
  libgcrypt/mpi/mpicoder.cpp
  libgcrypt/mpi/mpi-div.cpp
  libgcrypt/mpi/mpi-gcd.cpp
  libgcrypt/mpi/mpih-div.cpp
  libgcrypt/mpi/mpih-mul.cpp
  libgcrypt/mpi/mpi-inline.cpp
  libgcrypt/mpi/mpi-inv.cpp
  libgcrypt/mpi/mpi-mod.cpp
  libgcrypt/mpi/mpi-mpow.cpp
  libgcrypt/mpi/mpi-mul.cpp
  libgcrypt/mpi/mpi-pow.cpp
  libgcrypt/mpi/mpi-scan.cpp
  libgcrypt/mpi/mpiutil.cpp
  libgcrypt/mpi/mpih-add1.cpp
  libgcrypt/mpi/generic/mpih-lshift.cpp
  libgcrypt/mpi/generic/mpih-mul1.cpp
  libgcrypt/mpi/generic/mpih-mul2.cpp
  libgcrypt/mpi/generic/mpih-mul3.cpp
  libgcrypt/mpi/generic/mpih-rshift.cpp
  libgcrypt/mpi/generic/mpih-sub1.cpp
  libgcrypt/mpi/generic/udiv-w-sdiv.cpp
  libgcrypt/random/rand-internal.h
  libgcrypt/random/random.cpp
  libgcrypt/random/random-csprng.cpp
  libgcrypt/random/random-drbg.cpp
  libgcrypt/random/random-fips.cpp
  libgcrypt/random/random.h
  libgcrypt/random/random-system.cpp
  libgcrypt/random/rndhw.cpp
  libgcrypt/random/rndlinux.cpp
)
add_library(neopg::gcrypt ALIAS gcrypt)

target_include_directories(gcrypt PRIVATE
  libgpg-error/src
  libgcrypt/mpi
  libgcrypt/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gcrypt PRIVATE
  HAVE_CONFIG_H=1)

target_compile_options(gcrypt PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_executable(gcrypt-test
  libgcrypt/tests/hmac.cpp
  libgcrypt/tests/gcrypt-test.cpp)
target_include_directories(gcrypt-test PRIVATE
  libgpg-error/src
  libgcrypt/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_options(gcrypt-test PUBLIC -fpermissive -Wnarrowing -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)
target_link_libraries(gcrypt-test PRIVATE
  gcrypt
  gpg-error
  GTest::GTest GTest::Main)
add_test(GcryptTest gcrypt-test COMMAND gcrypt-test test_xml_output --gtest_output=xml:gcrypt-test.xml)

add_executable(gcrypt-secmem-test
  libgcrypt/tests/t-secmem.cpp
libgcrypt/tests/gcrypt-secmem-test.cpp)
target_include_directories(gcrypt-secmem-test PRIVATE
    libgpg-error/src
    libgcrypt/src
    ${CMAKE_BINARY_DIR}/.)
target_compile_options(gcrypt-secmem-test PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)
  target_link_libraries(gcrypt-secmem-test PRIVATE
    gcrypt
    gpg-error
    GTest::GTest GTest::Main)
  add_test(GcryptSecmemTest gcrypt-secmem-test COMMAND gcrypt-secmem-test test_xml_output --gtest_output=xml:gcrypt-secmem-test.xml)

# libksba

add_library(ksba
  libksba/src/ksba.h
  libksba/src/visibility.cpp
  libksba/src/reader.cpp
  libksba/src/writer.cpp
  libksba/src/asn1-parse.cpp
  libksba/src/asn1-func.cpp
  libksba/src/asn1-func2.cpp
  libksba/src/ber-help.cpp
  libksba/src/ber-decoder.cpp
  libksba/src/der-encoder.cpp
  libksba/src/cert.cpp
  libksba/src/cms.cpp
  libksba/src/cms-parser.cpp
  libksba/src/crl.cpp
  libksba/src/certreq.cpp
  libksba/src/ocsp.cpp
  libksba/src/keyinfo.cpp
  libksba/src/oid.cpp
  libksba/src/name.cpp
  libksba/src/dn.cpp
  libksba/src/time.cpp
  libksba/src/util.cpp
  libksba/src/asn1-tables.cpp
)
add_library(neopg::ksba ALIAS ksba)

target_include_directories(ksba PRIVATE
  libgpg-error/src
  libksba/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(ksba PRIVATE
  HAVE_CONFIG_H=1)

target_compile_options(ksba PUBLIC -fpermissive -U_GNU_SOURCE -D_POSIX_SOURCE=1 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

add_executable(ksba-test
  libksba/tests/ksba-test.cpp
  libksba/tests/t-oid.cpp
  libksba/tests/t-crl-parser.cpp
  libksba/tests/t-dnparser.cpp
  )
target_include_directories(ksba-test PRIVATE
  libgpg-error/src
  libksba/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(ksba-test PRIVATE
  CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/libksba/tests")
target_link_libraries(ksba-test PRIVATE
  gpg-error
  ksba
  GTest::GTest GTest::Main)
add_test(KsbaTest ksba-test COMMAND ksba-test test_xml_output --gtest_output=xml:ksba-test.xml)


FIND_PACKAGE(Boost COMPONENTS date_time REQUIRED)

# libneopg

set(LIBNEOPG_INCLUDE_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/lib)
set(LIBNEOPG_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/include)
set(LIBNEOPG_INCLUDE_DST ${LIBNEOPG_INCLUDE}/neopg)
configure_file(${LIBNEOPG_INCLUDE_SRC}/utils/time.h ${LIBNEOPG_INCLUDE_DST}/time.h COPYONLY)
configure_file(${LIBNEOPG_INCLUDE_SRC}/parser/openpgp.h ${LIBNEOPG_INCLUDE_DST}/openpgp.h COPYONLY)
configure_file(${LIBNEOPG_INCLUDE_SRC}/openpgp/tag.h ${LIBNEOPG_INCLUDE_DST}/openpgp/tag.h COPYONLY)

add_library(libneopg
  src/lib/utils/time.h
  src/lib/utils/time.cpp
  src/lib/parser/openpgp.h
  src/lib/openpgp/tag.h
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
  gnupg/common/logging.h
  gnupg/common/logging.cpp
  gnupg/common/sysutils.h
  gnupg/common/sysutils.cpp
  gnupg/common/utf8conv.h
  gnupg/common/utf8conv.cpp
  gnupg/common/stringhelp.h
  gnupg/common/stringhelp.cpp
  gnupg/common/server-help.h
  gnupg/common/server-help.cpp
  gnupg/common/argparse.h
  gnupg/common/argparse.cpp
  gnupg/common/strlist.h
  gnupg/common/strlist.cpp
  gnupg/common/membuf.h
  gnupg/common/membuf.cpp
  gnupg/common/status.h
  gnupg/common/status.cpp
  gnupg/common/iobuf.h
  gnupg/common/iobuf.cpp
  gnupg/common/i18n.h
  gnupg/common/i18n.cpp
  gnupg/common/gettime.h
  gnupg/common/gettime.cpp
  gnupg/common/asshelp.h
  gnupg/common/asshelp.cpp
  gnupg/common/dotlock.h
  gnupg/common/dotlock.cpp
  gnupg/common/mischelp.h
  gnupg/common/compliance.h
  gnupg/common/compliance.cpp
  gnupg/common/exechelp.h
  gnupg/common/exechelp-posix.cpp
  gnupg/common/userids.h
  gnupg/common/userids.cpp
  gnupg/common/mbox-util.h
  gnupg/common/mbox-util.cpp
  gnupg/common/recsel.h
  gnupg/common/recsel.cpp
  gnupg/common/gpgrlhelp.cpp
  gnupg/common/homedir.cpp
  gnupg/common/miscellaneous.cpp
  gnupg/common/init.cpp
  gnupg/common/percent.cpp
  gnupg/common/zb32.cpp
  gnupg/common/openpgp-oid.cpp
  gnupg/common/ttyio.cpp
  gnupg/common/xasprintf.cpp
  gnupg/common/yesno.cpp
  gnupg/common/sexputil.cpp
  gnupg/common/tlv.cpp
  gnupg/common/util.h
  gnupg/common/localename.cpp
  gnupg/common/convert.cpp
  gnupg/common/b64enc.cpp
  gnupg/kbx/keybox-init.cpp
  gnupg/kbx/keybox-util.cpp
  gnupg/kbx/keybox-blob.cpp
  gnupg/kbx/keybox-file.cpp
  gnupg/kbx/keybox-openpgp.cpp
  gnupg/kbx/keybox-update.cpp
  gnupg/kbx/keybox-search.cpp
  gnupg/g10/misc.cpp
  gnupg/g10/keyid.cpp
  gnupg/g10/keyserver.cpp
  gnupg/g10/pubkey-enc.cpp
  gnupg/g10/pkclist.cpp
  gnupg/g10/ecdh.cpp
  gnupg/g10/kbnode.cpp
  gnupg/g10/compress.cpp
  gnupg/g10/filter.h
  gnupg/g10/passphrase.cpp
  gnupg/g10/import.cpp
  gnupg/g10/export.cpp
  gnupg/g10/decrypt-data.cpp
  gnupg/g10/plaintext.cpp
  gnupg/g10/textfilter.cpp
  gnupg/g10/progress.cpp
  gnupg/g10/mdfilter.cpp
  gnupg/g10/seskey.cpp
  gnupg/g10/pkglue.cpp
  gnupg/g10/revoke.cpp
  gnupg/g10/sign.cpp
  gnupg/g10/encrypt.cpp
  gnupg/g10/decrypt.cpp
  gnupg/g10/cipher.cpp
  gnupg/g10/verify.cpp
  gnupg/g10/skclist.cpp
  gnupg/g10/keygen.cpp
  gnupg/g10/call-dirmngr.cpp
  gnupg/g10/call-agent.cpp
  gnupg/g10/getkey.cpp
  gnupg/g10/keydb.cpp
  gnupg/g10/packet.h
  gnupg/g10/build-packet.cpp
  gnupg/g10/parse-packet.cpp
  gnupg/g10/mainproc.cpp
  gnupg/g10/free-packet.cpp
  gnupg/g10/sig-check.cpp
  gnupg/g10/keyedit.cpp
  gnupg/g10/trust.cpp
  gnupg/g10/cpr.cpp
  gnupg/g10/keylist.cpp
  gnupg/g10/openfile.cpp
  gnupg/g10/key-check.cpp
  gnupg/g10/armor.cpp
  gnupg/g10/trustdb.cpp
  gnupg/g10/tdbio.cpp
  gnupg/g10/tdbdump.cpp
  gnupg/g10/exec.cpp
  gnupg/g10/delkey.cpp
  gnupg/g10/dearmor.cpp
  gnupg/g10/tofu.cpp
  gnupg/g10/card-util.cpp
  gnupg/g10/gpgsql.cpp
  gnupg/g10/compress-bz2.cpp
  gnupg/g10/gpg.cpp

  gnupg/agent/command.cpp
  gnupg/agent/gpg-agent.cpp
  gnupg/agent/protect.cpp
  gnupg/agent/call-scd.cpp
  gnupg/agent/findkey.cpp
  gnupg/agent/cvt-openpgp.cpp
  gnupg/agent/cache.cpp
  gnupg/agent/genkey.cpp
  gnupg/agent/call-pinentry.cpp
  gnupg/agent/trustlist.cpp
  gnupg/common/asshelp2.cpp
  gnupg/common/asshelp.h
  gnupg/agent/pkdecrypt.cpp
  gnupg/agent/pksign.cpp
  gnupg/agent/learncard.cpp
  gnupg/agent/divert-scd.cpp
  gnupg/common/name-value.cpp

  gnupg/dirmngr/dirmngr.cpp
  gnupg/dirmngr/crlfetch.cpp
  gnupg/dirmngr/dirmngr-client.cpp
  gnupg/dirmngr/dirmngr.cpp
  gnupg/dirmngr/dns-stuff.cpp
  gnupg/dirmngr/http-common.cpp
  gnupg/dirmngr/http.cpp
  gnupg/dirmngr/ks-action.cpp
  gnupg/dirmngr/ks-engine-hkp.cpp
  gnupg/dirmngr/ks-engine-http.cpp
  gnupg/dirmngr/ks-engine-kdns.cpp
  gnupg/dirmngr/misc.cpp
  gnupg/dirmngr/ocsp.cpp
  gnupg/dirmngr/server.cpp
  gnupg/dirmngr/validate.cpp
  gnupg/dirmngr/crlcache.cpp
  gnupg/dirmngr/certcache.cpp
  gnupg/dirmngr/cdblib.cpp
  gnupg/common/ksba-io-support.cpp
  gnupg/common/exectool.cpp

  gnupg/sm/call-agent.cpp
  gnupg/sm/certcheck.cpp
  gnupg/sm/certreqgen.cpp
  gnupg/sm/delete.cpp
  gnupg/sm/fingerprint.cpp
  gnupg/sm/sign.cpp
  gnupg/sm/call-dirmngr.cpp
  gnupg/sm/certdump.cpp
  gnupg/sm/certreqgen-ui.cpp
  gnupg/sm/encrypt.cpp
  gnupg/sm/gpgsm.cpp
  gnupg/sm/import.cpp
  gnupg/sm/keylist.cpp
  gnupg/sm/misc.cpp
  gnupg/sm/verify.cpp
  gnupg/sm/certchain.cpp
  gnupg/sm/certlist.cpp
  gnupg/sm/decrypt.cpp
  gnupg/sm/export.cpp
  gnupg/sm/keydb.cpp
  gnupg/sm/minip12.cpp
  gnupg/sm/passphrase.cpp
  gnupg/sm/server.cpp
  gnupg/sm/gpgsm.cpp

  gnupg/scd/scdaemon.cpp
  gnupg/scd/apdu.cpp
  gnupg/scd/app.cpp
  gnupg/scd/app-dinsig.cpp
  gnupg/scd/app-help.cpp
  gnupg/scd/app-nks.cpp
  gnupg/scd/app-p15.cpp
  gnupg/scd/app-sc-hsm.cpp
  gnupg/scd/app-openpgp.cpp
  gnupg/scd/atr.cpp
  gnupg/scd/ccid-driver.cpp
  gnupg/scd/command.cpp
  gnupg/scd/iso7816.cpp

  src/neopg.cpp
)
target_include_directories(neopg PRIVATE
  libgpg-error/src
  libassuan/src
  libgcrypt/src
  npth/src
  libksba/src
  ${CMAKE_BINARY_DIR}/.
  ${Boost_INCLUDE_DIR}
  ${SQLITE3_INCLUDE_DIRS}
  ${BOTAN2_INCLUDE_DIRS}
  ${LIBUSB_INCLUDE_DIRS}
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



#if(CMAKE_COMPILER_IS_GNUCXX)
#  target_compile_options(foo
#  PUBLIC -fno-...)
#endif()
#target_compile_features(foo
#PUBLIC cxx_auto_type
#PRIVATE
#cxx_variadic_templates)
