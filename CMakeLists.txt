cmake_minimum_required (VERSION 2.6)
project (AclTester)
set(CMAKE_BUILD_TYPE Debug)
# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/AclTesterConfig.h.in"
  "${PROJECT_BINARY_DIR}/AclTesterConfig.h"
  )
 
# add the binary tree to the search path for include files
# so that we will find AclTesterConfig.h
add_definitions(-DWITH_BROKER)
include_directories("${PROJECT_BINARY_DIR}")
add_library (p SHARED Plugin.c security_default.c)
add_executable(AclTester AclTester.c security_default.c)
add_executable(PluginTester PluginTester.c)
add_executable(hashtest hashtest.c)
target_link_libraries(PluginTester p)
