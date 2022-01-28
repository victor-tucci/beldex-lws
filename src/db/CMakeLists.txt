set(beldex-lws-db_sources account.cpp data.cpp storage.cpp string.cpp)
set(beldex-lws-db_headers account.h data.h fwd.h storage.h string.h)

add_library(beldex-lws-db ${beldex-lws-db_sources} ${beldex-lws-db_headers})
target_include_directories(beldex-lws-db PUBLIC "${LMDB_INCLUDE}")
target_link_libraries(beldex-lws-db beldex::libraries ${LMDB_LIB_PATH})
