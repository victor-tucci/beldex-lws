include_directories(.)

message( "--------- INSIDE THE LWS ------")

add_subdirectory(db)
add_subdirectory(util)
add_subdirectory(wire)
find_package(nlohmann_json 3.7.0 REQUIRED)
find_package(Boost 1.60 REQUIRED COMPONENTS regex)

set(beldex-lws-common_sources config.cpp error.cpp)
set(beldex-lws-common_headers config.h error.h fwd.h)

add_library(beldex-lws-common ${beldex-lws-common_sources} ${beldex-lws-common_headers})
target_link_libraries(beldex-lws-common beldex-lws-db)

add_executable(beldex-lws-daemon server_main.cpp rest_server.cpp scanner.cpp)

target_link_libraries(beldex-lws-daemon PUBLIC
    beldex-lws-db
    beldex-lws-common
    beldex-lws-util
    beldex-lws-wire-json
    PRIVATE
    Boost::serialization
    filesystem
    Boost::thread
    Boost::system
    Threads::Threads
    Boost::regex
)

target_link_libraries(beldex-lws-daemon PRIVATE nlohmann_json::nlohmann_json)

add_executable(beldex-lws-admin admin_main.cpp)
target_link_libraries(beldex-lws-admin PRIVATE 
beldex-lws-db
beldex-lws-common
beldex-lws-util
beldex-lws-wire-json
)

install(TARGETS beldex-lws-daemon DESTINATION bin)
install(TARGETS beldex-lws-admin DESTINATION bin)