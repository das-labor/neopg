cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(NeoPG VERSION 0.0 LANGUAGES C CXX)

include(CheckIncludeFiles)

check_include_files(malloc.h HAVE_MALLOC_H)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include (CheckFunctionExists)
check_function_exists (log HAVE_LOG)
check_function_exists (exp HAVE_EXP)

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
  ../libgpg-error/src/lock.h
  ../libgpg-error/src/thread.h
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

target_include_directories(gpg-error
  PRIVATE ../libgpg-error/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gpg-error
PRIVATE HAVE_CONFIG_H=1)
target_link_libraries(gpg-error PRIVATE pthread)

# FIXME tests
add_executable(testx ../libgpg-error/tests/t-strerror.c)
target_link_libraries(testx PRIVATE gpg-error)
target_include_directories(testx
  PRIVATE ../libgpg-error/src
  ${CMAKE_BINARY_DIR}/.)
#t-common.h  t-lock.c  t-poll.c  t-printf.c  t-strerror.c  t-syserror.c  t-version.c

add_executable(neopg neopg.cxx)
target_link_libraries(neopg PRIVATE gpg-error)

target_include_directories(neopg
PRIVATE ../libgpg-error/src
${CMAKE_BINARY_DIR}/.)

#target_compile_definitions(neopg
#    PRIVATE SRC_DIR={${Foo_SOURCE_DIR}
#    )
#if(CMAKE_COMPILER_IS_GNUCXX)
#  target_compile_options(foo
#  PUBLIC -fno-...)
#endif()
#target_compile_features(foo
#PUBLIC cxx_auto_type
#PRIVATE
#cxx_variadic_templates)
