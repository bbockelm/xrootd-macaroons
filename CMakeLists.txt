
cmake_minimum_required( VERSION 2.8 )
project( xrootd-macaroons )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

find_package( Xrootd REQUIRED )
find_package( Macaroons REQUIRED )

include (FindPkgConfig)
pkg_check_modules(JSON REQUIRED json-c)
pkg_check_modules(UUID REQUIRED uuid)
pkg_check_modules(LIBCRYPTO REQUIRED libcrypto)

macro(use_cxx11)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      set (CMAKE_CXX_FLAGS "-std=gnu++11 ${CMAKE_CXX_FLAGS}")
    endif ()
  else ()
    set (CMAKE_CXX_STANDARD 11)
  endif ()
endmacro(use_cxx11)
use_cxx11()

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()
SET( CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")
SET( CMAKE_MODULE_LINKER_FLAGS "-Wl,--no-undefined")

include_directories(${MACAROONS_INCLUDES} ${XROOTD_INCLUDES} ${XROOTD_PRIVATE_INCLUDES} ${JSON_INCLUDE_DIRS} ${UUID_INCLUDE_DIRS} ${LIBCRYPTO_INCLUDE_DIRS})

add_library(XrdMacaroons SHARED src/macaroons.cpp src/handler.cpp src/authz.cpp src/configure.cpp)
target_link_libraries(XrdMacaroons -ldl ${XROOTD_UTILS_LIB} ${XROOTD_SERVER_LIB} ${MACAROONS_LIB} ${JSON_LIBRARIES} ${XROOTD_HTTP_LIB} ${UUID_LIBRARIES} ${LIBCRYPTO_LIBRARIES})
set_target_properties(XrdMacaroons PROPERTIES OUTPUT_NAME XrdMacaroons-4 SUFFIX ".so" LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols")

SET(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Install path for libraries")

install(
  TARGETS XrdMacaroons
  LIBRARY DESTINATION ${LIB_INSTALL_DIR})
