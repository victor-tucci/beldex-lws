# Copyright (c) 2018, The Beldex Project
# Copyright (c) 2014-2018, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

add_library(wallet
  wallet2.cpp
  wallet_args.cpp
  ringdb.cpp
  node_rpc_proxy.cpp
  message_store.cpp
  message_transporter.cpp
  transfer_view.cpp
)

target_link_libraries(wallet
  PUBLIC
    multisig
    rpc_commands
    rpc_server_base
    cryptonote_core
    mnemonics
    device_trezor
    net
    lmdb
    rpc_http_client
    Boost::serialization
    filesystem
    Boost::thread
  PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    extra)

beldex_add_executable(wallet_rpc_server "beldex-wallet-rpc"
  wallet_rpc_server.cpp
  wallet_rpc_server_commands_defs.cpp
  )

target_link_libraries(wallet_rpc_server
  PRIVATE
    rpc_server_base
    wallet
    daemonizer
    Boost::program_options
    extra)


add_subdirectory(api)


###################################################################################
message("----------------wallet---------------------")
function(combine_archives output_archive)
  message("----------------function called------------------------")
  set(FULL_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/lib${output_archive}.a)
  set(output_archive_dummy_file ${CMAKE_CURRENT_BINARY_DIR}/${output_archive}.dummy.cpp)
  add_custom_command(OUTPUT ${output_archive_dummy_file}
                     COMMAND touch ${output_archive_dummy_file}
                     DEPENDS ${ARGN})
  add_library(${output_archive} STATIC EXCLUDE_FROM_ALL ${output_archive_dummy_file})

  if(NOT APPLE)
  message("----------------inside not apple function called------------------------")
    set(mri_file ${CMAKE_CURRENT_BINARY_DIR}/${output_archive}.mri)
    set(mri_content "create ${FULL_OUTPUT_PATH}\n")
    message("create ${FULL_OUTPUT_PATH}\n")
    foreach(in_archive ${ARGN})
        message("${ARGN}")
        string(APPEND mri_content "addlib $<TARGET_FILE:${in_archive}>\n")
    endforeach()
    string(APPEND mri_content "save\nend\n")
    file(GENERATE OUTPUT ${mri_file} CONTENT "${mri_content}")
    message("mri_files are : ${mri_file}")

    add_custom_command(TARGET ${output_archive}
                       POST_BUILD
                       COMMAND ar -M < ${mri_file})
  else()
  message("--------------------in else ----------------------------")
    set(merge_libs)
    foreach(in_archive ${ARGN})
      list(APPEND merge_libs $<TARGET_FILE:${in_archive}>)
    endforeach()
    add_custom_command(TARGET ${output_archive}
                       POST_BUILD
                       COMMAND /usr/bin/libtool -static -o ${FULL_OUTPUT_PATH} ${merge_libs})
  endif()
endfunction(combine_archives)

if (true)
message("------------merge functions--------------")
    set(merged_protobuf)
    if(TARGET protobuf_lite)
      set(merged_protobuf protobuf_lite)
    endif()

    combine_archives(wallet_merged
            #wallet_api
            wallet
            multisig
            cryptonote_core
            cryptonote_basic
            cryptonote_protocol
            mnemonics
            common
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

            # Static deps:
            Boost::program_options Boost::serialization Boost::system Boost::thread
            #zlib
            OpenSSL::SSL OpenSSL::Crypto
            #expat
            #libunbound
            #sqlite3
            #${merged_protobuf}
            #sodium
            #libzmq
            #CURL::libcurl
            oxenmq::oxenmq
            lmdb
            easylogging
            randomx
            uSockets
            cpr
            )

    if(IOS)
        set(lib_folder lib-${ARCH})
    else()
        set(lib_folder lib)
    endif()
    install(TARGETS wallet_merged
        ARCHIVE DESTINATION ${lib_folder}
        EXCLUDE_FROM_ALL)
endif()
            