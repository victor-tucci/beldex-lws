set(beldex-lws_wire-json_sources error.cpp read.cpp write.cpp)
set(beldex-lws_wire-json_headers base.h error.h fwd.h read.h write.h)

message( "--------- INSIDE THE LWS json------") 

add_library(beldex-lws-wire-json ${beldex-lws_wire-json_sources} ${beldex-lws-wire-json_headers})
target_link_libraries(beldex-lws-wire-json  beldex-lws-db beldex-lws-wire)
