cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(NeoPG VERSION 0.0 LANGUAGES C CXX)

enable_testing()
find_package(GTest REQUIRED)


include(CheckIncludeFiles)
check_include_files(malloc.h HAVE_MALLOC_H)

include (CheckFunctionExists)
check_function_exists (log HAVE_LOG)
check_function_exists (exp HAVE_EXP)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# libgpg-error

add_library(gpg-error
  ../libgpg-error/src/gpg-error.h
  ../libgpg-error/src/b64dec.cpp
  ../libgpg-error/src/code-from-errno.cpp
  ../libgpg-error/src/code-to-errno.cpp
  ../libgpg-error/src/strsource.cpp
  ../libgpg-error/src/strerror.cpp
  ../libgpg-error/src/estream.h
  ../libgpg-error/src/estream.cpp
  ../libgpg-error/src/estream-printf.cpp
  ../libgpg-error/src/gpg-error.h
  ../libgpg-error/src/gpgrt.h
  ../libgpg-error/src/gpgrt-int.h
  ../libgpg-error/src/init.h
  ../libgpg-error/src/init.cpp
  ../libgpg-error/src/visibility.h
  ../libgpg-error/src/visibility.cpp
  ../libgpg-error/src/gettext.h
)

if(WIN32)
  target_sources(gpg-error PRIVATE
    ../libgpg-error/src/w32-add.h
    ../libgpg-error/src/w32-estream.cpp
    ../libgpg-error/src/w32-gettext.cpp
    ../libgpg-error/src/w32-iconv.cpp
    ../libgpg-error/src/w32-lock.cpp
    ../libgpg-error/src/w32-thread.cpp
  )
else()
  target_sources(gpg-error PRIVATE
  ../libgpg-error/src/posix-lock.cpp
  ../libgpg-error/src/posix-thread.cpp
)
endif()

add_library(neopg::gpg-error ALIAS gpg-error)

target_include_directories(gpg-error PRIVATE
  ../libgpg-error/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gpg-error PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(gpg-error PRIVATE pthread)
target_compile_options(gpg-error PUBLIC -fpermissive)

add_executable(gpg-error-test
  ../libgpg-error/tests/t-b64dec.cpp
  ../libgpg-error/tests/t-lock.cpp
  ../libgpg-error/tests/t-poll.cpp
  ../libgpg-error/tests/t-printf.cpp
  ../libgpg-error/tests/t-strerror.cpp
  ../libgpg-error/tests/t-syserror.cpp
  ../libgpg-error/tests/gpg-error-test.cpp
)
target_include_directories(gpg-error-test PRIVATE
  ../libgpg-error/src
  ${CMAKE_BINARY_DIR}/.)
target_link_libraries(gpg-error-test PRIVATE
  gpg-error
  GTest::GTest GTest::Main)
add_test(GpgErrorTest gpg-error-test COMMAND gpg-error-test test_xml_output --gtest_output=xml:gpg-error-test.xml)

# libassuan

add_library(assuan
  ../libassuan/src/assuan-buffer.cpp
  ../libassuan/src/assuan-defs.h
  ../libassuan/src/assuan-error.cpp
  ../libassuan/src/assuan-handler.cpp
  ../libassuan/src/assuan-inquire.cpp
  ../libassuan/src/assuan-io.cpp
  ../libassuan/src/assuan-listen.cpp
  ../libassuan/src/assuan-logging.cpp
  ../libassuan/src/assuan-pipe-connect.cpp
  ../libassuan/src/assuan-pipe-server.cpp
  ../libassuan/src/assuan-socket-connect.cpp
  ../libassuan/src/assuan-socket-server.cpp
  ../libassuan/src/assuan-socket.cpp
  ../libassuan/src/assuan-uds.cpp
  ../libassuan/src/assuan.cpp
  ../libassuan/src/assuan.h
  ../libassuan/src/client.cpp
  ../libassuan/src/context.cpp
  ../libassuan/src/conversion.cpp
  ../libassuan/src/debug.cpp
  ../libassuan/src/debug.h
  ../libassuan/src/server.cpp
  ../libassuan/src/system.cpp
  ../libassuan/src/sysutils.cpp
)

if(WIN32)
  target_sources(assuan PRIVATE
    ../libassuan/src/system-w32.cpp
  )
else()
  target_sources(assuan PRIVATE
    ../libassuan/src/system-posix.cpp
)
endif()

target_compile_options(assuan PUBLIC -fpermissive)

add_library(neopg::assuan ALIAS assuan)

target_include_directories(assuan PRIVATE
  ../libgpg-error/src
  ../libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(assuan PRIVATE gpg-error)

add_executable(assuan-test
  ../libassuan/tests/fdpassing.cpp
  ../libassuan/tests/assuan-test.cpp)
target_include_directories(assuan-test PRIVATE
  ../libgpg-error/src
  ../libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan-test PRIVATE
CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/../libassuan/tests")
target_compile_options(assuan-test PUBLIC -fpermissive)
target_link_libraries(assuan-test PRIVATE
  assuan
  GTest::GTest GTest::Main)
add_test(AssuanTest assuan-test COMMAND assuan-test test_xml_output --gtest_output=xml:assuan-test.xml)

# npth

add_library(npth
  ../npth/src/npth.h
  ../npth/src/npth.cpp
  ../npth/src/npth-sigev.cpp
)
add_library(neopg::npth ALIAS npth)

target_include_directories(npth PRIVATE
  ../npth/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(npth PRIVATE
  HAVE_CONFIG_H=1)

target_compile_options(npth PUBLIC -fpermissive)

add_executable(npth-test
  ../npth/tests/t-fork.cpp
  ../npth/tests/t-mutex.cpp
  ../npth/tests/t-support.h
  ../npth/tests/t-thread.cpp
  ../npth/tests/npth-test.cpp)
target_include_directories(npth-test PRIVATE
  ../npth/src
  ${CMAKE_BINARY_DIR}/.)
target_link_libraries(npth-test PRIVATE
  npth
  GTest::GTest GTest::Main)
add_test(nPthTest npth-test COMMAND npth-test test_xml_output --gtest_output=xml:npth-test.xml)

# libgcrypt

add_library(gcrypt
  ../libgcrypt/src/cipher-proto.h
  ../libgcrypt/src/cipher.h
  ../libgcrypt/src/context.c
  ../libgcrypt/src/context.h
  ../libgcrypt/src/ec-context.h
  ../libgcrypt/src/fips.c
  ../libgcrypt/src/g10lib.h
  ../libgcrypt/src/gcrypt-int.h
  ../libgcrypt/src/gcrypt-testapi.h
  ../libgcrypt/src/gcrypt.h
  ../libgcrypt/src/global.c
  ../libgcrypt/src/hmac256.c
  ../libgcrypt/src/hmac256.h
  ../libgcrypt/src/hwf-common.h
  ../libgcrypt/src/hwf-x86.c
  ../libgcrypt/src/hwfeatures.c
  ../libgcrypt/src/misc.c
  ../libgcrypt/src/mpi.h
  ../libgcrypt/src/secmem.c
  ../libgcrypt/src/secmem.h
  ../libgcrypt/src/sexp.c
  ../libgcrypt/src/stdmem.c
  ../libgcrypt/src/stdmem.h
  ../libgcrypt/src/types.h
  ../libgcrypt/src/visibility.c
  ../libgcrypt/src/visibility.h
  ../libgcrypt/cipher/blake2.c
  ../libgcrypt/cipher/crc.c
  ../libgcrypt/cipher/ecc.c
  ../libgcrypt/cipher/ecc-curves.c
  ../libgcrypt/cipher/ecc-eddsa.c
  ../libgcrypt/cipher/ecc-gost.c
  ../libgcrypt/cipher/ecc-misc.c
  ../libgcrypt/cipher/ecc-ecdsa.c
  ../libgcrypt/cipher/elgamal.c
  ../libgcrypt/cipher/dsa.c
  ../libgcrypt/cipher/rsa.c
  ../libgcrypt/cipher/sha1.c
  ../libgcrypt/cipher/sha256.c
  ../libgcrypt/cipher/sha512.c
  ../libgcrypt/cipher/keccak.c
  ../libgcrypt/cipher/whirlpool.c
  ../libgcrypt/cipher/md4.c
  ../libgcrypt/cipher/md5.c
  ../libgcrypt/cipher/tiger.c
  ../libgcrypt/cipher/gostr3411-94.c
  ../libgcrypt/cipher/gost28147.c
  ../libgcrypt/cipher/stribog.c
  ../libgcrypt/cipher/rmd160.c
  ../libgcrypt/cipher/blowfish.c
  ../libgcrypt/cipher/camellia.c
  ../libgcrypt/cipher/camellia-glue.c
  ../libgcrypt/cipher/salsa20.c
  ../libgcrypt/cipher/rijndael.c
  ../libgcrypt/cipher/idea.c
  ../libgcrypt/cipher/des.c
  ../libgcrypt/cipher/arcfour.c
  ../libgcrypt/cipher/cast5.c
  ../libgcrypt/cipher/twofish.c
  ../libgcrypt/cipher/rfc2268.c
  ../libgcrypt/cipher/seed.c
  ../libgcrypt/cipher/chacha20.c
  ../libgcrypt/cipher/mac-cmac.c
  ../libgcrypt/cipher/serpent.c
  ../libgcrypt/cipher/cipher.c
  ../libgcrypt/cipher/cipher-internal.h
  ../libgcrypt/cipher/cipher-cbc.c
  ../libgcrypt/cipher/cipher-cfb.c
  ../libgcrypt/cipher/cipher-ofb.c
  ../libgcrypt/cipher/cipher-ctr.c
  ../libgcrypt/cipher/cipher-aeswrap.c
  ../libgcrypt/cipher/cipher-ccm.c
  ../libgcrypt/cipher/cipher-cmac.c
  ../libgcrypt/cipher/cipher-gcm.c
  ../libgcrypt/cipher/cipher-poly1305.c
  ../libgcrypt/cipher/cipher-ocb.c
  ../libgcrypt/cipher/cipher-xts.c
  ../libgcrypt/cipher/cipher-selftest.c
  ../libgcrypt/cipher/cipher-selftest.h
  ../libgcrypt/cipher/pubkey.c
  ../libgcrypt/cipher/pubkey-internal.h
  ../libgcrypt/cipher/pubkey-util.c
  ../libgcrypt/cipher/md.c
  ../libgcrypt/cipher/mac.c
  ../libgcrypt/cipher/mac-internal.h
  ../libgcrypt/cipher/mac-hmac.c
  ../libgcrypt/cipher/mac-cmac.c
  ../libgcrypt/cipher/mac-gmac.c
  ../libgcrypt/cipher/mac-poly1305.c
  ../libgcrypt/cipher/poly1305.c
  ../libgcrypt/cipher/poly1305-internal.h
  ../libgcrypt/cipher/kdf.c
  ../libgcrypt/cipher/scrypt.c
  ../libgcrypt/cipher/kdf-internal.h
  ../libgcrypt/cipher/hmac-tests.c
  ../libgcrypt/cipher/bithelp.h
  ../libgcrypt/cipher/bufhelp.h
  ../libgcrypt/cipher/primegen.c
  ../libgcrypt/cipher/hash-common.c
  ../libgcrypt/cipher/hash-common.h
  ../libgcrypt/cipher/dsa-common.c
  ../libgcrypt/cipher/rsa-common.c
  ../libgcrypt/cipher/sha1.h
  ../libgcrypt/mpi/ec.c
  ../libgcrypt/mpi/mpi-add.c
  ../libgcrypt/mpi/mpi-bit.c
  ../libgcrypt/mpi/mpi-cmp.c
  ../libgcrypt/mpi/mpicoder.c
  ../libgcrypt/mpi/mpi-div.c
  ../libgcrypt/mpi/mpi-gcd.c
  ../libgcrypt/mpi/mpih-div.c
  ../libgcrypt/mpi/mpih-mul.c
  ../libgcrypt/mpi/mpi-inline.c
  ../libgcrypt/mpi/mpi-inv.c
  ../libgcrypt/mpi/mpi-mod.c
  ../libgcrypt/mpi/mpi-mpow.c
  ../libgcrypt/mpi/mpi-mul.c
  ../libgcrypt/mpi/mpi-pow.c
  ../libgcrypt/mpi/mpi-scan.c
  ../libgcrypt/mpi/mpiutil.c
  ../libgcrypt/mpi/mpih-add1.c
  ../libgcrypt/mpi/generic/mpih-lshift.c
  ../libgcrypt/mpi/generic/mpih-mul1.c
  ../libgcrypt/mpi/generic/mpih-mul2.c
  ../libgcrypt/mpi/generic/mpih-mul3.c
  ../libgcrypt/mpi/generic/mpih-rshift.c
  ../libgcrypt/mpi/generic/mpih-sub1.c
  ../libgcrypt/mpi/generic/udiv-w-sdiv.c
  ../libgcrypt/random/rand-internal.h
  ../libgcrypt/random/random.c
  ../libgcrypt/random/random-csprng.c
  ../libgcrypt/random/random-drbg.c
  ../libgcrypt/random/random-fips.c
  ../libgcrypt/random/random.h
  ../libgcrypt/random/random-system.c
  ../libgcrypt/random/rndhw.c
  ../libgcrypt/random/rndlinux.c
)
add_library(neopg::gcrypt ALIAS gcrypt)

target_include_directories(gcrypt PRIVATE
  ../libgpg-error/src
  ../libgcrypt/mpi
  ../libgcrypt/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gcrypt PRIVATE
  HAVE_CONFIG_H=1)

add_executable(gcrypt-test
  ../libgcrypt/tests/hmac.c
  ../libgcrypt/tests/gcrypt-test.cpp)
target_include_directories(gcrypt-test PRIVATE
  ../libgpg-error/src
  ../libgcrypt/src
  ${CMAKE_BINARY_DIR}/.)
target_link_libraries(gcrypt-test PRIVATE
  gcrypt
  gpg-error
  GTest::GTest GTest::Main)
add_test(GcryptTest gcrypt-test COMMAND gcrypt-test test_xml_output --gtest_output=xml:gcrypt-test.xml)

add_executable(gcrypt-secmem-test
  ../libgcrypt/tests/t-secmem.c
../libgcrypt/tests/gcrypt-secmem-test.cpp)
  target_include_directories(gcrypt-secmem-test PRIVATE
    ../libgpg-error/src
    ../libgcrypt/src
    ${CMAKE_BINARY_DIR}/.)
  target_link_libraries(gcrypt-secmem-test PRIVATE
    gcrypt
    gpg-error
    GTest::GTest GTest::Main)
  add_test(GcryptSecmemTest gcrypt-secmem-test COMMAND gcrypt-secmem-test test_xml_output --gtest_output=xml:gcrypt-secmem-test.xml)

# gpg

add_executable(neopg
  ../gnupg/common/logging.h
  ../gnupg/common/logging.c
  ../gnupg/common/sysutils.h
  ../gnupg/common/sysutils.c
  ../gnupg/common/utf8conv.h
  ../gnupg/common/utf8conv.c
  ../gnupg/common/stringhelp.h
  ../gnupg/common/stringhelp.c
  ../gnupg/common/server-help.h
  ../gnupg/common/server-help.c
  ../gnupg/common/argparse.h
  ../gnupg/common/argparse.c
  ../gnupg/common/strlist.h
  ../gnupg/common/strlist.c
  ../gnupg/common/membuf.h
  ../gnupg/common/membuf.c
  ../gnupg/common/status.h
  ../gnupg/common/status.c
  ../gnupg/common/iobuf.h
  ../gnupg/common/iobuf.c
  ../gnupg/common/i18n.h
  ../gnupg/common/i18n.c
  ../gnupg/common/session-env.h
  ../gnupg/common/session-env.c
  ../gnupg/common/gettime.h
  ../gnupg/common/gettime.c
  ../gnupg/common/asshelp.h
  ../gnupg/common/asshelp.c
  ../gnupg/common/dotlock.h
  ../gnupg/common/dotlock.c
  ../gnupg/common/mischelp.h
  ../gnupg/common/mischelp.c
  ../gnupg/common/compliance.h
  ../gnupg/common/compliance.c
  ../gnupg/common/exechelp.h
  ../gnupg/common/exechelp-posix.c
  ../gnupg/common/userids.h
  ../gnupg/common/userids.c
  ../gnupg/common/mbox-util.h
  ../gnupg/common/mbox-util.c
  ../gnupg/common/recsel.h
  ../gnupg/common/recsel.c
  ../gnupg/common/gpgrlhelp.c
  ../gnupg/common/homedir.c
  ../gnupg/common/mapstrings.c
  ../gnupg/common/miscellaneous.c
  ../gnupg/common/init.c
  ../gnupg/common/percent.c
  ../gnupg/common/signal.c
  ../gnupg/common/zb32.c
  ../gnupg/common/openpgp-oid.c
  ../gnupg/common/ttyio.c
  ../gnupg/common/xasprintf.c
  ../gnupg/common/yesno.c
  ../gnupg/common/sexputil.c
  ../gnupg/common/tlv.c
  ../gnupg/common/helpfile.c
  ../gnupg/common/util.h
  ../gnupg/common/localename.c
  ../gnupg/common/convert.c
  ../gnupg/common/b64enc.c
  ../gnupg/common/agent-opt.c
  ../gnupg/kbx/keybox-init.c
  ../gnupg/kbx/keybox-util.c
  ../gnupg/kbx/keybox-blob.c
  ../gnupg/kbx/keybox-file.c
  ../gnupg/kbx/keybox-openpgp.c
  ../gnupg/kbx/keybox-update.c
  ../gnupg/kbx/keybox-search.c
  ../gnupg/g10/misc.c
  ../gnupg/g10/photoid.c
  ../gnupg/g10/keyid.c
  ../gnupg/g10/keyserver.c
  ../gnupg/g10/keyring.c
  ../gnupg/g10/pubkey-enc.c
  ../gnupg/g10/pkclist.c
  ../gnupg/g10/ecdh.c
  ../gnupg/g10/kbnode.c
  ../gnupg/g10/compress.c
  ../gnupg/g10/filter.h
  ../gnupg/g10/passphrase.c
  ../gnupg/g10/import.c
  ../gnupg/g10/export.c
  ../gnupg/g10/decrypt-data.c
  ../gnupg/g10/plaintext.c
  ../gnupg/g10/textfilter.c
  ../gnupg/g10/progress.c
  ../gnupg/g10/mdfilter.c
  ../gnupg/g10/seskey.c
  ../gnupg/g10/pkglue.c
  ../gnupg/g10/revoke.c
  ../gnupg/g10/sign.c
  ../gnupg/g10/encrypt.c
  ../gnupg/g10/decrypt.c
  ../gnupg/g10/cipher.c
  ../gnupg/g10/verify.c
  ../gnupg/g10/skclist.c
  ../gnupg/g10/keygen.c
  ../gnupg/g10/helptext.c
  ../gnupg/g10/call-dirmngr.c
  ../gnupg/g10/call-agent.c
  ../gnupg/g10/getkey.c
  ../gnupg/g10/keydb.c
  ../gnupg/g10/packet.h
  ../gnupg/g10/build-packet.c
  ../gnupg/g10/parse-packet.c
  ../gnupg/g10/mainproc.c
  ../gnupg/g10/free-packet.c
  ../gnupg/g10/sig-check.c
  ../gnupg/g10/keyedit.c
  ../gnupg/g10/rmd160.h
  ../gnupg/g10/rmd160.c
  ../gnupg/g10/trust.c
  ../gnupg/g10/cpr.c
  ../gnupg/g10/keylist.c
  ../gnupg/g10/openfile.c
  ../gnupg/g10/key-check.c
  ../gnupg/g10/armor.c
  ../gnupg/g10/trustdb.c
  ../gnupg/g10/tdbio.c
  ../gnupg/g10/tdbdump.c
  ../gnupg/g10/exec.c
  ../gnupg/g10/server.c
  ../gnupg/g10/migrate.c
  ../gnupg/g10/delkey.c
  ../gnupg/g10/dearmor.c
  ../gnupg/g10/gpg.c)
target_include_directories(neopg PRIVATE
  ../libgpg-error/src
  ../libassuan/src
  ../libgcrypt/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(neopg PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(neopg PRIVATE
    gpg-error
    assuan
  gcrypt)
target_compile_options(neopg PUBLIC -fpermissive)

#if(CMAKE_COMPILER_IS_GNUCXX)
#  target_compile_options(foo
#  PUBLIC -fno-...)
#endif()
#target_compile_features(foo
#PUBLIC cxx_auto_type
#PRIVATE
#cxx_variadic_templates)
