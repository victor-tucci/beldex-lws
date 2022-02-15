include_directories(.)

message( "--------- INSIDE THE LWS ------")

add_subdirectory(db)
add_subdirectory(rpc)
add_subdirectory(util)
add_subdirectory(wire)

set(beldex-lws-common_sources config.cpp error.cpp)
set(beldex-lws-common_headers config.h error.h fwd.h)

add_library(beldex-lws-common ${beldex-lws-common_sources} ${beldex-lws-common_headers})
target_link_libraries(beldex-lws-common beldex-lws-db)

add_executable(beldex-lws-daemon server_main.cpp scanner.cpp rest_server.cpp)

target_link_libraries(beldex-lws-daemon PUBLIC
    beldex-lws-db
    beldex-lws-common
    beldex-lws-wire-json
    beldex-lws-rpc
    beldex-lws-util
    PRIVATE
    Boost::serialization
    filesystem
    Boost::thread
    Boost::system
)

add_executable(beldex-lws-admin admin_main.cpp)
target_link_libraries(beldex-lws-admin
  PRIVATE
    beldex-lws-common
    beldex-lws-db
    beldex-lws-wire-json
)

install(TARGETS beldex-lws-daemon DESTINATION bin)
install(TARGETS beldex-lws-admin DESTINATION bin)