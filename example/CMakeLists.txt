# Copyright 2022 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

add_executable (veraison_challenge_response challenge_response.c)

target_include_directories (veraison_challenge_response PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)

target_link_libraries(
    veraison_challenge_response 
    PUBLIC veraison
    debug "${CMAKE_SOURCE_DIR}/shim/target/debug/libveraison_client_shim.a"
    optimized "${CMAKE_SOURCE_DIR}/shim/target/release/libveraison_client_shim.a")

