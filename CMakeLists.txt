# Copyright 2022 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required (VERSION 3.18.1)
project (VERAISON_API_CLIENT)
include (ExternalProject)

# This folder contains the Veraison C client library itself
add_subdirectory (lib)

# This folder builds an example executable program that exercises the Veraison C client
add_subdirectory (example)

# Add an external project for the Rust shim. The Veraison C client library is not actually implemented in C.
# The C client is actually a wrapper of the Rust client. We need to build a C-callable shim around the Rust
# client and create a staticlib target, which is what this external project does.
ExternalProject_Add(
    shim
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cargo build COMMAND cargo build --release
    BINARY_DIR shim
    INSTALL_COMMAND ""
    LOG_BUILD ON)

# The C client library depends on the C-callable Rust client shim
add_dependencies(veraison shim)
