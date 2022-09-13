include_directories(.)

message( "--------- INSIDE THE LWS ------")

add_subdirectory(db)
add_subdirectory(rpc)
add_subdirectory(util)
add_subdirectory(wire)

find_package(nlohmann_json 3.7.0 REQUIRED)

set(beldex-lws-common_sources config.cpp error.cpp)
set(beldex-lws-common_headers config.h error.h fwd.h)

add_library(beldex-lws-common ${beldex-lws-common_sources} ${beldex-lws-common_headers})
target_link_libraries(beldex-lws-common beldex-lws-db)

add_executable(beldex-lws-daemon server_main.cpp scanner.cpp)

target_link_libraries(beldex-lws-daemon PUBLIC
    beldex-lws-db
    beldex-lws-common
    beldex-lws-rpc
    beldex-lws-util
    PRIVATE
    Boost::serialization
    filesystem
    Boost::thread
    Boost::system
    Threads::Threads
)
target_link_libraries(beldex-lws-daemon PRIVATE nlohmann_json::nlohmann_json)

add_executable(beldex-lws-admin admin_main.cpp)
target_link_libraries(beldex-lws-admin PRIVATE 
beldex-lws-db
beldex-lws-common
beldex-lws-wire-json
)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin )
# install(TARGETS beldex-lws-daemon DESTINATION bin)
# install(TARGETS beldex-lws-admin DESTINATION bin)
