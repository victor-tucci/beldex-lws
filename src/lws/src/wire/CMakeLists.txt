set(beldex-lws-wire_sources error.cpp read.cpp write.cpp)
set(beldex-lws-wire_headers crypto.h error.h field.h filters.h fwd.h json.h read.h traits.h vector.h write.h)

message( "--------- INSIDE THE LWS wire------") 

add_library(beldex-lws-wire ${beldex-lws-wire_sources} ${beldex-lws-wire_headers})
target_include_directories(beldex-lws-wire PUBLIC "${LMDB_INCLUDE}")
target_link_libraries(beldex-lws-wire PRIVATE beldex-lws-db)

add_subdirectory(json)