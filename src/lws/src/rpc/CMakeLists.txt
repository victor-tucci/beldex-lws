set(beldex-lws-rpc_sources daemon_zmq.cpp client.cpp light_wallet.cpp)
set(beldex-lws-rpc_headers daemon_zmq.h fwd.h json.h light_wallet.h client.h)

add_library(beldex-lws-rpc ${beldex-lws-rpc_sources} ${beldex-lws-rpc_headers})
target_link_libraries(beldex-lws-rpc beldex-lws-db beldex-lws-wire-json)