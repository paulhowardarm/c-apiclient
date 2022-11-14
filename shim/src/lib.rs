// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CStr, CString};

use core::slice;

use veraison_apiclient::{ChallengeResponseBuilder, Error, Nonce};

pub struct ChallengeResponseSession {
    session_url: *const libc::c_char,
    nonce_size: libc::size_t,
    nonce: *const u8,
    accept_type_count: libc::size_t,
    accept_type_list: *const *const libc::c_char,
}

#[no_mangle]
pub extern "C" fn open_challenge_response_session(
    base_url: *const libc::c_char,
    nonce_size: libc::size_t,
    nonce: *const u8,
    session: *mut ChallengeResponseSession,
) -> u32 {
    let url_str: &str = unsafe {
        let url_cstr = CStr::from_ptr(base_url);
        url_cstr.to_str().unwrap()
    };

    let nonce_converted: Nonce = {
        if nonce == std::ptr::null() {
            // Null pointer implies a request for the server to generate the nonce
            // of the given size. The size is also permitted to be zero, in which case
            // the server will choose the size as well as generating the nonce.
            Nonce::Size(nonce_size)
        } else {
            // Non-null pointer means we are making a Nonce::Value variant of the
            // given size.
            let bytes = unsafe { slice::from_raw_parts(nonce, nonce_size) };
            Nonce::Value(Vec::from(bytes))
        }
    };

    let challenge_response = ChallengeResponseBuilder::new()
        .with_base_url(url_str.to_owned())
        .build()
        .unwrap();

    0
}
