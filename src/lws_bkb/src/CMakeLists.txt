include_directories(.)

message( "--------- INSIDE THE LWS ------")

add_subdirectory(db)

set(monero-lws-common_sources config.cpp error.cpp)
set(monero-lws-common_headers config.h error.h fwd.h)

add_library(monero-lws-common ${monero-lws-common_sources} ${monero-lws-common_headers})
target_link_libraries(monero-lws-common beldex-lws-db)

add_executable(beldex-lws-daemon server_main.cpp scanner.cpp)

target_link_libraries(beldex-lws-daemon PUBLIC
    beldex-lws-db
    monero-lws-common
    PRIVATE
    Boost::serialization
    filesystem
    Boost::thread
    Boost::system
)


install(TARGETS beldex-lws-daemon DESTINATION bin)