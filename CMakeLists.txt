cmake_minimum_required(VERSION 3.1.0)
project(beldex-lws)

enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(BELDEX_LIBRARIES
common
)

set(BELDEX_SEARCH_PATHS
"/src"
)

#
# Pull some information from BELDEX build
#

# Needed due to "bug" in beldex CMake - the `project` function is used twice!

if (NOT BELDEX_SOURCE_DIR)
  message(FATAL_ERROR "The argument -DBELDEX_SOURCE_DIR must specify a location of a beldex source tree")
endif()

if (NOT BELDEX_BUILD_DIR)
  message(FATAL_ERROR "The argument -DBELDEX_BUILD_DIR must specify a location of an existing beldex build")
endif()

load_cache(${BELDEX_BUILD_DIR} READ_WITH_PREFIX beldex_
  Boost_THREAD_LIBRARY_RELEASE
  CMAKE_CXX_COMPILER
  EXTRA_LIBRARIES
  HIDAPI_LIBRARY
  LMDB_INCLUDE
  beldex_SOURCE_DIR
  OPENSSL_CRYPTO_LIBRARY
  OPENSSL_SSL_LIBRARY
  SODIUM_LIBRARY
  UNBOUND_LIBRARIES
  ZMQ_INCLUDE_PATH
  ZMQ_LIB
)

# if (NOT (beldex_beldex_SOURCE_DIR MATCHES "${BELDEX_SOURCE_DIR}(/src/cryptonote_protocol)"))
#   message(FATAL_ERROR "Invalid Monero source dir - does not appear to match source used for build directory")
# endif()

if (NOT (CMAKE_CXX_COMPILER STREQUAL beldex_CMAKE_CXX_COMPILER))
  message(FATAL_ERROR "Compiler for beldex build differs from this project")
endif()

if ("${beldex_UNBOUND_LIBRARIES}" STREQUAL "UNBOUND_LIBRARIES-NOTFOUND")
  unset(beldex_UNBOUND_LIBRARIES)
endif()

if ("${beldex_HIDAPI_LIBRARY}" STREQUAL "HIDAPI_LIBRARY-NOTFOUND")
  unset(beldex_HIDAPI_LIBRARY)
endif()

#
# Dependencies specific to beldex-lws
#

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(Boost_NO_BOOST_CMAKE ON)
find_package(Boost 1.58 QUIET REQUIRED COMPONENTS chrono filesystem program_options regex serialization system thread)

if (NOT (Boost_THREAD_LIBRARY STREQUAL beldex_Boost_THREAD_LIBRARY_RELEASE))
  message(STATUS "Found Boost_THREAD_LIBRARY: ${Boost_THREAD_LIBRARY}")
  message(STATUS "Found beldex_Boost_THREAD_LIBRARY_RELEASE: ${beldex_Boost_THREAD_LIBRARY_RELEASE}")
  message(FATAL_ERROR "Boost libraries for beldex build differs from this project")
endif()

foreach (LIB ${BELDEX_LIBRARIES})
  find_library(LIB_PATH NAMES "${LIB}" PATHS ${BELDEX_BUILD_DIR} PATH_SUFFIXES "/src/${LIB}" "external/${LIB}" ${BELDEX_SEARCH_PATHS} NO_DEFAULT_PATH)

  list(FIND BELDEX_OPTIONAL "${LIB}" LIB_OPTIONAL)
  if (NOT LIB_PATH)
    if (LIB_OPTIONAL EQUAL -1)
      message(FATAL_ERROR "Unable to find required Monero library ${LIB}")
    endif()
  else ()
    set(LIB_NAME "beldex::${LIB}")
    add_library(${LIB_NAME} STATIC IMPORTED)
    set_target_properties(${LIB_NAME} PROPERTIES IMPORTED_LOCATION ${LIB_PATH})
    list(APPEND IMPORTED_BELDEX_LIBRARIES "${LIB_NAME}")
  endif()
  
  unset(LIB_PATH CACHE)
endforeach()

add_library(beldex::libraries INTERFACE IMPORTED)
set_property(TARGET beldex::libraries PROPERTY
  INTERFACE_INCLUDE_DIRECTORIES
    ${Boost_INCLUDE_DIR}
    "${BELDEX_BUILD_DIR}/generated_include"
    "${BELDEX_SOURCE_DIR}/contrib/epee/include"
    "${BELDEX_SOURCE_DIR}/external/easylogging++"
    "${BELDEX_SOURCE_DIR}/external/loki-mq"
    "${BELDEX_SOURCE_DIR}/external/rapidjson/include"
    "${BELDEX_SOURCE_DIR}/src"
)
set_property(TARGET beldex::libraries PROPERTY
  INTERFACE_LINK_LIBRARIES
    ${IMPORTED_BELDEX_LIBRARIES}
    ${Boost_CHRONO_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_REGEX_LIBRARY}
    ${Boost_SERIALIZATION_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${beldex_HIDAPI_LIBRARY}
    ${beldex_OPENSSL_CRYPTO_LIBRARY}
    ${beldex_OPENSSL_SSL_LIBRARY}
    ${beldex_SODIUM_LIBRARY}
    ${beldex_UNBOUND_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

set(LMDB_INCLUDE "${beldex_LMDB_INCLUDE}")
set(LMDB_LIB_PATH "beldex::lmdb")
set(ZMQ_LIB "${beldex_ZMQ_LIB}")
set(ZMQ_INCLUDE_PATH "${beldex_ZMQ_INCLUDE_PATH}")


#
# Build beldex-lws code
#

add_subdirectory(src)
