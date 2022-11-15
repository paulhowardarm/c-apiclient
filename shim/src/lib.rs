// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{c_void, CStr, CString};

use core::slice;

use veraison_apiclient::{ChallengeResponseBuilder, Error, Nonce};

#[repr(C)]
pub struct ShimRawChallengeResponseSession {
    session_url: *const libc::c_char,
    nonce_size: libc::size_t,
    nonce: *const u8,
    accept_type_count: libc::size_t,
    accept_type_list: *const *const libc::c_char,
    session_wrapper: *mut c_void,
}

struct ShimChallengeResponseSession {
    session_url_cstring: CString,
    nonce_vec: Vec<u8>,
    accept_type_cstring_vec: Vec<CString>,
    accept_type_ptr_vec: Vec<*const libc::c_char>,
}

#[no_mangle]
pub extern "C" fn open_challenge_response_session(
    base_url: *const libc::c_char,
    nonce_size: libc::size_t,
    nonce: *const u8,
    out_session: *mut *mut ShimRawChallengeResponseSession,
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

    // From here on in, just fake everything to get the FFI layer correct.
    let fake_nonce = match nonce_converted {
        // If the nonce is a size, just ignore the size and use a vector of 8 bytes as the fake
        // server-generated nonce.
        Nonce::Size(_) => vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],

        // Nonce is supplied by the caller, so just clone it.
        Nonce::Value(v) => v.clone(),
    };

    let mut fake_media_types = Vec::new();
    fake_media_types.push(String::from("application/fake-test-media-type-1"));
    fake_media_types.push(String::from("application/fake-test-media-type-2"));
    fake_media_types.push(String::from("application/fake-test-media-type-3"));
    fake_media_types.push(String::from("application/fake-test-media-type-4"));

    let mut fake_session_url = String::from(url_str);
    fake_session_url.push_str("/sessions/fake/1234");

    let media_type_cstrings = fake_media_types
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut shim_session = ShimChallengeResponseSession {
        session_url_cstring: CString::new(fake_session_url.as_str()).unwrap(),
        nonce_vec: fake_nonce.clone(),
        accept_type_cstring_vec: media_type_cstrings,
        accept_type_ptr_vec: Vec::with_capacity(fake_media_types.len()),
    };

    for s in &shim_session.accept_type_cstring_vec {
        shim_session.accept_type_ptr_vec.push(s.as_ptr())
    }

    let raw_shim_session = Box::new(ShimRawChallengeResponseSession {
        session_url: shim_session.session_url_cstring.as_ptr(),
        nonce_size: shim_session.nonce_vec.len(),
        nonce: shim_session.nonce_vec.as_ptr(),
        accept_type_count: shim_session.accept_type_ptr_vec.len(),
        accept_type_list: shim_session.accept_type_ptr_vec.as_ptr(),
        session_wrapper: Box::into_raw(Box::new(shim_session)) as *mut c_void,
    });

    let session_ptr = Box::into_raw(raw_shim_session);
    unsafe { *out_session = session_ptr };

    0
}

#[no_mangle]
pub extern "C" fn free_challenge_response_session(
    session: *mut ShimRawChallengeResponseSession,
) -> () {
    // Just re-box the session and let Rust drop it all automatically.
    let raw_session = unsafe { Box::from_raw(session) };
    let _ = unsafe { Box::from_raw(raw_session.session_wrapper as *mut ShimChallengeResponseSession)};
}
