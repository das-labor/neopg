add_custom_target(release
   WORKING_DIRECTORY ${PROJECT_BUILD_DIR}
   COMMAND ${CMAKE_COMMAND} -Ds=${PROJECT_SOURCE_DIR} -Du=${GitRelease_USER} -Dp=${GitRelease_PROJECT} -P ${PROJECT_SOURCE_DIR}/cmake/GitReleaseScript.cmake
)

find_program(GEN_CHANGELOG github_changelog_generator)
add_custom_target(changelog
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
   COMMAND ${GEN_CHANGELOG} -u ${GitRelease_USER} -p ${GitRelease_PROJECT} --header-label '\# Changelog'
   COMMAND sed -i '/This Change Log was automatically generated/d' ${PROJECT_SOURCE_DIR}/CHANGELOG.md
)
