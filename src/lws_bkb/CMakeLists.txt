add_executable(beldex-lws-daemon main.cpp)
message( "--------- INSIDE THE LWS ------")
# target_include_directories(beldex-lws-daemon PUBLIC "${BELDEX_SOURCE_DIR}/src" ${ZMQ_INCLUDE_PATH})
target_link_libraries(beldex-lws-daemon PUBLIC
common
cryptonote_format_utils
hardfork
wallet
multisig
cryptonote_core
cryptonote_basic
cryptonote_protocol
mnemonics
cncrypto
device
ringct
ringct_basic
checkpoints
version
net
device_trezor
epee
blockchain_db
rpc_http_client
rpc_commands
daemon_messages
OpenSSL::SSL OpenSSL::Crypto
oxenmq::oxenmq
lmdb
easylogging
randomx
uSockets
cpr

)


set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin )
