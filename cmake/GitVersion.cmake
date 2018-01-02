# NeoPG - cmake file
# Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

# This file defines two variables:
# - GIT_VERSION_STRING with the format "1.2.3" usable for cmake project()
# - GIT_VERSION_STRING_FULL with the format "v1.2.3-TAG-NUMBER-ID-dirty"
# where any part but the version number may be omitted (see git-describe).

find_package(Git)

set(GIT_VERSION_STRING_FULL "")

if(GIT_FOUND)
  execute_process(
       # Travis CI makes a shallow clone (depth 50) which may not
       # include any tags.  Fallback with --always, but note that in
       # this case we might not have a version number after all.
       COMMAND ${GIT_EXECUTABLE} describe --tags --dirty --always
       OUTPUT_VARIABLE GIT_VERSION_STRING_FULL
       RESULT_VARIABLE GIT_VERSION_DESCRIBE_RESULT
       OUTPUT_STRIP_TRAILING_WHITESPACE
  )
else()
  set(GIT_VERSION_DESCRIBE_RESULT -1)
endif()

# In case we couldn't find a version tag with git, we add the one from
# the file VERSION.
if(NOT GIT_VERSION_DESCRIBE_RESULT EQUAL 0 OR NOT GIT_VERSION_STRING_FULL MATCHES "^v[0-9]+\.[0-9]+\.[0-9]+")
  # CMAKE_SOURCE_DIR is valid even before project() is called.
  file(READ ${CMAKE_SOURCE_DIR}/VERSION VERSION_STRING)
  string(STRIP "${VERSION_STRING}" VERSION_STRING)

  if(NOT GIT_VERSION_STRING_FULL STREQUAL "")
    set(VERSION_STRING "${VERSION_STRING}-${GIT_VERSION_STRING_FULL}")
  endif()
  set(GIT_VERSION_STRING_FULL "${VERSION_STRING}")
endif()

# Possible results:
# "v0.0.3-56-g396a0b4": git describe found a version tag.
# "v0.0.3-mytag-10-g396a0b4": git describe found another tag, we added version from file
# "v0.0.3-396a0b4-dirty": no tags, we added version from file

# Find major, minor, patch
string(REGEX REPLACE "^v|-.*$" "" GIT_VERSION_STRING "${GIT_VERSION_STRING_FULL}")
