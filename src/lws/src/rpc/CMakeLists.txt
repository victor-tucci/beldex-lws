
set(beldex-lws-rpc_sources client.cpp daemon_pub.cpp daemon_zmq.cpp light_wallet.cpp rates.cpp)
set(beldex-lws-rpc_headers client.h daemon_pub.h daemon_zmq.h fwd.h json.h light_wallet.h rates.h)

message( "--------- INSIDE THE LWS rpc------") 

add_library(beldex-lws-rpc ${beldex-lws-rpc_sources} ${beldex-lws-rpc_headers})
target_link_libraries(beldex-lws-rpc beldex-lws-db beldex-lws-wire-json)
