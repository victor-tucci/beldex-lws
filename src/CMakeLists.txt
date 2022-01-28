
include_directories(.)
add_subdirectory(db)

set(beldex-lws-common_sources config.cpp error.cpp)
set(beldex-lws-common_headers config.h error.h fwd.h)

add_library(beldex-lws-common ${beldex-lws-common_sources} ${beldex-lws-common_headers})
target_link_libraries(beldex-lws-common beldex::libraries)

add_executable(beldex-lws-daemon server_main.cpp rest_server.cpp scanner.cpp)

# For the server 
target_include_directories(beldex-lws-daemon PUBLIC ${ZMQ_INCLUDE_PATH})
target_link_libraries(beldex-lws-daemon
  PRIVATE
    beldex::libraries
    ${BELDEX_lmdb}
    beldex-lws-common
    beldex-lws-db
    ${Boost_CHRONO_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES}
    ${ZMQ_LIB}
    Threads::Threads
)

install(TARGETS beldex-lws-daemon DESTINATION bin)