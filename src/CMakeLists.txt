

# For both the server and admin utility.
set(monero-lws-common_sources config.cpp error.cpp)
set(monero-lws-common_headers config.h error.h fwd.h)

add_executable(monero-lws-daemon server_main.cpp rest_server.cpp scanner.cpp)
target_include_directories(monero-lws-daemon PUBLIC ${ZMQ_INCLUDE_PATH})
target_link_libraries(monero-lws-daemon
  PRIVATE
    beldex::libraries
    ${MONERO_lmdb}
    beldex-lws-common
    ${Boost_CHRONO_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES}
    ${ZMQ_LIB}
    Threads::Threads
)

