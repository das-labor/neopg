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
  ../libgpg-error/src/b64dec.c
  ../libgpg-error/src/code-from-errno.c
  ../libgpg-error/src/code-to-errno.c
  ../libgpg-error/src/strsource.c
  ../libgpg-error/src/strerror.c
  ../libgpg-error/src/estream.h
  ../libgpg-error/src/estream.c
  ../libgpg-error/src/estream-printf.c
  ../libgpg-error/src/gpg-error.h
  ../libgpg-error/src/gpgrt.h
  ../libgpg-error/src/gpgrt-int.h
  ../libgpg-error/src/init.h
  ../libgpg-error/src/init.c
  ../libgpg-error/src/visibility.h
  ../libgpg-error/src/visibility.c
  ../libgpg-error/src/gettext.h
)

if(WIN32)
  target_sources(gpg-error PRIVATE
    ../libgpg-error/src/w32-add.h
    ../libgpg-error/src/w32-estream.c
    ../libgpg-error/src/w32-gettext.c
    ../libgpg-error/src/w32-iconv.c
    ../libgpg-error/src/w32-lock.c
    ../libgpg-error/src/w32-thread.c
  )
else()
  target_sources(gpg-error PRIVATE
  ../libgpg-error/src/posix-lock.c
  ../libgpg-error/src/posix-thread.c
)
endif()

add_library(neopg::gpg-error ALIAS gpg-error)

target_include_directories(gpg-error PRIVATE
  ../libgpg-error/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gpg-error PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(gpg-error PRIVATE pthread)

add_executable(gpg-error-test
  ../libgpg-error/tests/t-b64dec.c
  ../libgpg-error/tests/t-lock.c
  ../libgpg-error/tests/t-poll.c
  ../libgpg-error/tests/t-printf.c
  ../libgpg-error/tests/t-strerror.c
  ../libgpg-error/tests/t-syserror.c
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
  ../libassuan/src/assuan-buffer.c
  ../libassuan/src/assuan-defs.h
  ../libassuan/src/assuan-error.c
  ../libassuan/src/assuan-handler.c
  ../libassuan/src/assuan-inquire.c
  ../libassuan/src/assuan-io.c
  ../libassuan/src/assuan-listen.c
  ../libassuan/src/assuan-logging.c
  ../libassuan/src/assuan-pipe-connect.c
  ../libassuan/src/assuan-pipe-server.c
  ../libassuan/src/assuan-socket-connect.c
  ../libassuan/src/assuan-socket-server.c
  ../libassuan/src/assuan-socket.c
  ../libassuan/src/assuan-uds.c
  ../libassuan/src/assuan.c
  ../libassuan/src/assuan.h
  ../libassuan/src/client.c
  ../libassuan/src/context.c
  ../libassuan/src/conversion.c
  ../libassuan/src/debug.c
  ../libassuan/src/debug.h
  ../libassuan/src/server.c
  ../libassuan/src/system.c
  ../libassuan/src/sysutils.c
)

if(WIN32)
  target_sources(assuan PRIVATE
    ../libassuan/src/system-w32.c
  )
else()
  target_sources(assuan PRIVATE
    ../libassuan/src/system-posix.c
)
endif()

add_library(neopg::assuan ALIAS assuan)

target_include_directories(assuan PRIVATE
  ../libgpg-error/src
  ../libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(assuan PRIVATE gpg-error)

add_executable(assuan-test
  ../libassuan/tests/fdpassing.c
  ../libassuan/tests/assuan-test.cpp)
target_include_directories(assuan-test PRIVATE
  ../libgpg-error/src
  ../libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan-test PRIVATE
CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/../libassuan/tests")
target_link_libraries(assuan-test PRIVATE
  assuan
  GTest::GTest GTest::Main)
add_test(AssuanTest assuan-test COMMAND assuan-test test_xml_output --gtest_output=xml:assuan-test.xml)



#if(CMAKE_COMPILER_IS_GNUCXX)
#  target_compile_options(foo
#  PUBLIC -fno-...)
#endif()
#target_compile_features(foo
#PUBLIC cxx_auto_type
#PRIVATE
#cxx_variadic_templates)
