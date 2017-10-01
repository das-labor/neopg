project(gpg-error)

cmake_minimum_required(VERSION 2.6)

############## the options that can be set from outside ##########################################
#option(BUILD_STATIC         "build a static library and no shared library"  OFF)
option(BUILD_TOOL           "build with tool executable"                    ON)
option(BUILD_TESTS          "build with test executables"                   ON)
option(BUILD_CROSS_TOOLS    "use external tools"                            ON)

if(BUILD_TESTS)
    enable_testing()
endif(BUILD_TESTS)

############## search for external tools that are needed for header generation ###################
find_program(AWK_EXECUTABLE NAMES awk gawk)

if(NOT AWK_EXECUTABLE)
    message(FATAL_ERROR "awk wasn't found. Please install it.")
else(NOT AWK_EXECUTABLE)
    message(STATUS "Found awk: ${AWK_EXECUTABLE}")
endif(NOT AWK_EXECUTABLE)

find_program(GREP_EXECUTABLE grep)

if(NOT GREP_EXECUTABLE)
    message(FATAL_ERROR "grep wasn't found. Please install it.")
else(NOT GREP_EXECUTABLE)
    message(STATUS "Found grep: ${GREP_EXECUTABLE}")
endif(NOT GREP_EXECUTABLE)

############## include the configure checks and set some import basic variables ##################
include(ConfigureChecks.cmake)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(BIN_DIR ${CMAKE_CURRENT_BINARY_DIR})

include_directories(${BIN_DIR} ${SRC_DIR})

if(WIN32)
    set(NULL_DEVICE 2> NUL)
else(WIN32)
    set(NULL_DEVICE 2> /dev/null)
endif(WIN32)

# For debugging purposes
# set(NULL_DEVICE)

# if set, TARGET_CPP is the compiler of the target platform
if(TARGET_CPP)
    set(ERR_COMPILER ${TARGET_CPP})
    set(INCLUDE_STRING "%TARGET_INCLUDE%")
else(TARGET_CPP)
    set(ERR_COMPILER ${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_ARG1})
	set(HOST_COMPILER ${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_ARG1})
    set(INCLUDE_STRING "%INCLUDE%")
endif(TARGET_CPP)

############## generate files ####################################################################
file(WRITE ${BIN_DIR}/extra-h.in "")
if(WIN32)
    file(READ ${SRC_DIR}/w32-add.h W32ADD_TMP)
    file(APPEND ${BIN_DIR}/extra-h.in "${W32ADD_TMP}")
endif(WIN32)
if(WINCE)
    file(READ ${SRC_DIR}/w32ce-add.h W32CEADD_TMP)
    file(APPEND ${BIN_DIR}/extra-h.in "${W32CEADD_TMP}")
	add_definitions(-DGPG_ERR_ENABLE_ERRNO_MACROS)
endif(WINCE)
file(APPEND ${BIN_DIR}/extra-h.in "\nEOF")

if(WINCE)
#	file(WRITE ${BIN_DIR}/gpg-extra/errno.h "/* some CE compat taken over from dbus */
#ifdef HAVE_W32CE_SYSTEM
#include <windows.h>
#define errno ((int)GetLastError ())
#define abort() exit(3)

#ifndef TLS_OUT_OF_INDEXES
# define TLS_OUT_OF_INDEXES 0xffffffff
#endif

#define EINVAL      ERROR_INVALID_PARAMETER
#define ERANGE      ERROR_ARITHMETIC_OVERFLOW
#define ENOMEM      ERROR_NOT_ENOUGH_MEMORY
#endif /* HAVE_W32CE_SYSTEM */
#")
endif(WINCE)

set(gpg_error_GENERATED_SRCS)

macro(awk_generate _filename _script)
    add_custom_command(OUTPUT ${BIN_DIR}/${_filename} COMMAND ${AWK_EXECUTABLE} -f ${SRC_DIR}/${_script} 
                                                                     ${ARGN}
                                                                     > ${BIN_DIR}/${_filename})
    set(gpg_error_GENERATED_SRCS ${gpg_error_GENERATED_SRCS} ${BIN_DIR}/${_filename})
endmacro(awk_generate _filename _options)

awk_generate(err-sources.h mkstrtable.awk -v textidx=3 ${SRC_DIR}/err-sources.h.in)
awk_generate(err-sources-sym.h mkstrtable.awk -v textidx=2 -v nogettext=1 ${SRC_DIR}/err-sources.h.in)
awk_generate(err-codes.h mkstrtable.awk -v textidx=3 ${SRC_DIR}/err-codes.h.in)
awk_generate(err-codes-sym.h mkstrtable.awk -v textidx=2 -v nogettext=1 ${SRC_DIR}/err-codes.h.in)
awk_generate(errnos-sym.h mkstrtable.awk -v textidx=2 -v nogettext=1 -v prefix=GPG_ERR_ -v namespace=errnos_ ${SRC_DIR}/errnos.in)
awk_generate(code-to-errno.h mkerrnos.awk ${SRC_DIR}/errnos.in)
awk_generate(gpg-error.h mkheader.awk ${SRC_DIR}/err-sources.h.in ${SRC_DIR}/err-codes.h.in ${SRC_DIR}/errnos.in ${BIN_DIR}/extra-h.in ${SRC_DIR}/gpg-error.h.in)

if(MSVC)
    # TODO: Rename to a not that crappy name.
    set(COMPILER_SPECIFIC_PREPROCECC_COMMAND -E)
else()
    set(COMPILER_SPECIFIC_PREPROCECC_COMMAND -E -P)
endif()
add_custom_command(OUTPUT ${BIN_DIR}/mkerrcodes.h  COMMAND ${AWK_EXECUTABLE} -f ${SRC_DIR}/mkerrcodes1.awk ${SRC_DIR}/errnos.in > ${BIN_DIR}/_mkerrcodes.h
                                                   #COMMAND set INCLUDE="\"${INCLUDE_STRING}\""
                                                   COMMAND ${ERR_COMPILER} ${COMPILER_SPECIFIC_PREPROCECC_COMMAND} ${BIN_DIR}/_mkerrcodes.h ${NULL_DEVICE} | "\"${GREP_EXECUTABLE}\"" GPG_ERR_ | 
                                                       "\"${AWK_EXECUTABLE}\"" -f ${SRC_DIR}/mkerrcodes.awk > ${BIN_DIR}/mkerrcodes.h)
add_custom_command(OUTPUT ${BIN_DIR}/mkw32errmap.tab.h COMMAND ${ERR_COMPILER} ${COMPILER_SPECIFIC_PREPROCECC_COMMAND} -DRESOLVE_MACROS ${SRC_DIR}/mkw32errmap.c ${NULL_DEVICE} | "\"${GREP_EXECUTABLE}\"" \"{&mkw32errmap_marker\" > ${BIN_DIR}/mkw32errmap.tab.h)

if(BUILD_CROSS_TOOLS)
    add_executable(mkw32errmap src/mkw32errmap.c ${BIN_DIR}/mkw32errmap.tab.h)
    add_executable(mkerrcodes ${BIN_DIR}/mkerrcodes.h src/mkerrcodes.c)
    get_target_property(MKW32ERRMAP mkw32errmap LOCATION)
    get_target_property(MKERRCODES mkerrcodes LOCATION)
    if(TARGET_CPP)
        # if TARGET_CPP is set, we want to compile for another platform. To get the correct 
        install(TARGETS mkw32errmap mkerrcodes RUNTIME DESTINATION bin
                                               LIBRARY DESTINATION lib
                                               ARCHIVE DESTINATION lib)
    endif(TARGET_CPP)
else(BUILD_CROSS_TOOLS)
    find_program(MKW32ERRMAP mkw32errmap)
    find_program(MKERRCODES mkerrcodes)
    if(NOT MKW32ERRMAP OR NOT MKERRCODES)
        message(FATAL_ERROR "could not find mkw32errmap or mkerrcodes")
    endif(NOT MKW32ERRMAP OR NOT MKERRCODES)
    message(STATUS "${MKW32ERRMAP} - ${MKERRCODES}")
	include_directories(${BIN_DIR}/gpg-extra)
endif(BUILD_CROSS_TOOLS)

if(WINCE)
	file(MAKE_DIRECTORY ${BIN_DIR}/gpg-extra)
    add_custom_command(OUTPUT ${BIN_DIR}/mkw32errmap.map.c COMMAND ${MKW32ERRMAP} --map > ${BIN_DIR}/mkw32errmap.map.c DEPENDS ${MKW32ERRMAP})
    add_custom_command(OUTPUT ${BIN_DIR}/gpg-extra/errno.h COMMAND ${MKW32ERRMAP} > ${BIN_DIR}/gpg-extra/errno.h DEPENDS ${MKW32ERRMAP})
	install(FILES ${BIN_DIR}/gpg-extra/errno.h DESTINATION include/gpg-extra)
else(WINCE)
    file(WRITE ${BIN_DIR}/mkw32errmap.map.c "/*dummy*/")
endif(WINCE)

add_custom_command(OUTPUT ${BIN_DIR}/code-from-errno.h COMMAND ${MKERRCODES} | "\"${AWK_EXECUTABLE}\"" -f ${SRC_DIR}/mkerrcodes2.awk > ${BIN_DIR}/code-from-errno.h DEPENDS ${MKERRCODES})
set(gpg_error_GENERATED_SRCS ${gpg_error_GENERATED_SRCS} ${BIN_DIR}/code-from-errno.h)

file(READ ${SRC_DIR}/gpg-error.def.in GPG_ERROR_DEF_TMP)
file(WRITE ${BIN_DIR}/gpg-error.def.h "${GPG_ERROR_DEF_TMP}")

add_custom_command(OUTPUT ${BIN_DIR}/gpg-error.def COMMAND ${ERR_COMPILER} -E -I "${BIN_DIR}" "${BIN_DIR}/gpg-error.def.h" ${NULL_DEVICE} | "\"${GREP_EXECUTABLE}\"" -v "\"^#\"" > ${BIN_DIR}/gpg-error.def.tmp
                                                   COMMAND ${GREP_EXECUTABLE} -v "\"^$$\"" ${BIN_DIR}/gpg-error.def.tmp > ${BIN_DIR}/gpg-error.def
                                                   DEPENDS ${BIN_DIR}/gpg-error.def.h)

set(gpg_error_SRCS
    mkw32errmap.map.c
    src/init.c
    src/strsource.c
    src/strerror.c
    src/code-to-errno.c
    src/code-from-errno.c
    src/version.c
)

if(WIN32)
    set(gpg_error_SRCS
        ${gpg_error_SRCS}
        src/w32-gettext.c
    )
    
    if(MSVC OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel"))
        add_definitions(-D_CRT_SECURE_NO_WARNINGS -Dinline=__inline -D__inline__=__inline -wd4996 -Dstrncasecmp=_strnicmp -Dstrcasecmp=_stricmp)
        if ((MSVC AND MSVC_VERSION LESS 1900)  OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel"))
            add_definitions(-Dsnprintf=_snprintf)
        endif()
    endif(MSVC OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel"))
	if(WINCE)
		set(gpg_error_SRCS
			${BIN_DIR}/gpg-extra/errno.h
			${gpg_error_SRCS}
		)
	endif(WINCE)
endif(WIN32)

#if(BUILD_STATIC)
#    set(_shared STATIC)
#else(BUILD_STATIC)
    set(_shared SHARED)
    set(gpg_error_SRCS ${gpg_error_SRCS} ${BIN_DIR}/gpg-error.def)
#endif(BUILD_STATIC)

add_library(libgpg-error ${_shared} ${gpg_error_SRCS} ${gpg_error_GENERATED_SRCS})
set_target_properties(libgpg-error PROPERTIES DEFINE_SYMBOL DLL_EXPORT)

if(BUILD_TOOL)
    set(gpg_error_SRCS
        src/strsource-sym.c
        src/strerror-sym.c
        src/gpg-error.c 
    )
    add_executable(gpg-error ${gpg_error_SRCS})

    target_link_libraries(gpg-error libgpg-error)
    set(gpg_error_target gpg-error)
else(BUILD_TOOL)
    set(gpg_error_target)
endif(BUILD_TOOL)

if(BUILD_TESTS)
    add_executable(t-strerror tests/t-strerror.c)
    target_link_libraries(t-strerror libgpg-error)
    add_test(t-strerror t-strerror)
    add_executable(t-syserror tests/t-syserror.c)
    target_link_libraries(t-syserror libgpg-error)
    add_test(t-syserror t-syserror)
    add_executable(t-version tests/t-version.c)
    target_link_libraries(t-version libgpg-error)
    add_test(t-version t-version)
endif(BUILD_TESTS)

install(TARGETS libgpg-error ${gpg_error_target}    RUNTIME DESTINATION bin
                                                    LIBRARY DESTINATION lib
                                                    ARCHIVE DESTINATION lib)

install(FILES ${BIN_DIR}/gpg-error.h DESTINATION include)
if(WIN32 AND NOT BUILD_STATIC)
    install(FILES ${BIN_DIR}/gpg-error.def DESTINATION lib)
endif(WIN32 AND NOT BUILD_STATIC)
