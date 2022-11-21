// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{c_void, CStr, CString};

use core::slice;

use veraison_apiclient::{ChallengeResponse, ChallengeResponseBuilder, Error, Nonce};

/// C-compatible representation of the challenge-response session.
#[repr(C)]
pub struct ShimRawChallengeResponseSession {
    session_url: *const libc::c_char,
    nonce_size: libc::size_t,
    nonce: *const u8,
    accept_type_count: libc::size_t,
    accept_type_list: *const *const libc::c_char,
    attestation_result: *const libc::c_char,
    message: *const libc::c_char,
    session_wrapper: *mut c_void, // Opaque pointer to ShimCallengeResponseSession
}

/// C-compatible enum representation of the error enum from the Rust client.
#[repr(C)]
pub enum ShimResult {
    Ok = 0,
    ConfigError,
    ApiError,
    CallbackError,
    NotImplementedError,
}

/// This structure contains the Rust-managed objects that are behind the raw pointers sent back to C
/// world. This structure is not visible to C other than as an opaque (void*) pointer. Think of it as
/// being like the private part of a public/private interface.
struct ShimChallengeResponseSession {
    client: Box<Option<ChallengeResponse>>,
    session_url_cstring: CString,
    nonce_vec: Vec<u8>,
    accept_type_cstring_vec: Vec<CString>,
    accept_type_ptr_vec: Vec<*const libc::c_char>,
    attestation_result_cstring: CString,
    message_cstring: CString,
}

#[no_mangle]
pub extern "C" fn open_challenge_response_session(
    base_url: *const libc::c_char,
    nonce_size: libc::size_t,
    nonce: *const u8,
    out_session: *mut *mut ShimRawChallengeResponseSession,
) -> ShimResult {
    // Unsafe region because we have to trust the caller's char* ptr.
    let url_str: &str = unsafe {
        let url_cstr = CStr::from_ptr(base_url);
        url_cstr.to_str().unwrap()
    };

    // Make a Nonce variant according to the given nonce_size and nonce arguments. If the nonce is null,
    // this implies the Nonce::Size() variant, otherwise it's the Nonce::Value() variant.
    let nonce_converted: Nonce = {
        if nonce == std::ptr::null() {
            // Null pointer implies a request for the server to generate the nonce
            // of the given size. The size is also permitted to be zero, in which case
            // the server will choose the size as well as generating the nonce.
            Nonce::Size(nonce_size)
        } else {
            // Non-null pointer means we are making a Nonce::Value variant of the
            // given size. We have to trust the caller's pointer here, hence unsafe region.
            let bytes = unsafe { slice::from_raw_parts(nonce, nonce_size) };
            Nonce::Value(Vec::from(bytes))
        }
    };

    // Establish the client session.
    let cr = ChallengeResponseBuilder::new()
        .with_base_url(String::from(url_str))
        .build();

    // Early return on error. The idiom here is slightly odd, and it arguably would be better to use
    // is_err() and expect_err(), but these require the underlying types to implement the Debug trait,
    // which they don't.
    match cr {
        Ok(_) => {}
        Err(e) => {
            // Early return with a stub session containing the error message.
            return stub_session_from_error(&e, out_session);
        }
    }

    // This now won't panic because we dealt with errors by early return above.
    let cr = cr.unwrap();

    let newsession = cr.new_session(&nonce_converted);

    match newsession {
        Ok(_) => {}
        Err(e) => {
            // Early return with a stub session containing the error message.
            return stub_session_from_error(&e, out_session);
        }
    }

    // This now won't panic because we dealt with errors by early return above.
    let (session_uri, session) = newsession.unwrap();

    let session_nonce = session.nonce().to_vec();
    let session_accept_types = session.accept().to_vec();

    // Map the Rust Strings to CString objects for the accept types.
    let media_type_cstrings = session_accept_types
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    // Make the ShimChallengeResponse session, which houses the Rust-compatible objects in order to manage
    // their memory in Rust world. This object is not visible to C world other than as an opaque pointer
    // that can be recovered later.
    let mut shim_session = ShimChallengeResponseSession {
        client: Box::new(Some(cr)),
        session_url_cstring: CString::new(session_uri.as_str()).unwrap(),
        nonce_vec: session_nonce.clone(),
        accept_type_cstring_vec: media_type_cstrings,
        accept_type_ptr_vec: Vec::with_capacity(session_accept_types.len()),
        attestation_result_cstring: CString::new("").unwrap(),
        message_cstring: CString::new("").unwrap(),
    };

    // Get the ptr (char*) for each CString and also store that in a Rust-managed Vec.
    for s in &shim_session.accept_type_cstring_vec {
        shim_session.accept_type_ptr_vec.push(s.as_ptr())
    }

    // Now make the ShimRawChallengeResponseSession, which houses the C-compatible types and is the structure
    // that C world sees. It is made out of interior pointers into the Rust data structure above.
    let raw_shim_session = Box::new(ShimRawChallengeResponseSession {
        session_url: shim_session.session_url_cstring.as_ptr(),
        nonce_size: shim_session.nonce_vec.len(),
        nonce: shim_session.nonce_vec.as_ptr(),
        accept_type_count: shim_session.accept_type_ptr_vec.len(),
        accept_type_list: shim_session.accept_type_ptr_vec.as_ptr(),
        // The attestation result is not known at this stage - it gets populated later.
        attestation_result: std::ptr::null(),
        // No message at this point
        message: std::ptr::null(),
        // Use Box::into_raw() to "release" the Rust memory so that the pointers all remain valid.
        session_wrapper: Box::into_raw(Box::new(shim_session)) as *mut c_void,
    });

    // Finally, use Box::into_raw() again for the raw session, so that Rust doesn't dispose it when it
    // drops out of scope.
    // C world will pass this pointer back to us in free_challenge_response_session(), at which point
    // we do Box::from_raw() to bring the memory back under Rust management.
    let session_ptr = Box::into_raw(raw_shim_session);
    unsafe { *out_session = session_ptr };

    ShimResult::Ok
}

#[no_mangle]
pub extern "C" fn challenge_response(
    session: *mut ShimRawChallengeResponseSession,
    evidence_size: libc::size_t,
    evidence: *const u8,
    media_type: *const libc::c_char,
) -> ShimResult {
    // Unsafe because we need to trust the caller's pointer
    let mut raw_session = unsafe { Box::from_raw(session) };

    let mut shim_session =
        unsafe { Box::from_raw(raw_session.session_wrapper as *mut ShimChallengeResponseSession) };

    // Unsafe because we need to trust the caller's pointer
    let media_type_str: &str = unsafe {
        let url_cstr = CStr::from_ptr(media_type);
        url_cstr.to_str().unwrap()
    };

    // Unsafe because we need to trust the caller's pointer and size
    let evidence_bytes = unsafe { slice::from_raw_parts(evidence, evidence_size) };

    // Actually call the client
    let client_result = match shim_session.client.as_ref() {
        Some(client) => client.challenge_response(
            evidence_bytes,
            media_type_str,
            shim_session.session_url_cstring.to_str().unwrap(),
        ),
        // If we have no client, it means that the session was never properly established in the first place.
        None => Err(Error::ConfigError(
            "Cannot supply evidence because there is no session endpoint.".to_string(),
        )),
    };

    let returncode = match client_result {
        Ok(attestation_result) => {
            shim_session.attestation_result_cstring = CString::new(attestation_result).unwrap();
            raw_session.attestation_result = shim_session.attestation_result_cstring.as_ptr();
            ShimResult::Ok
        }
        Err(e) => {
            let (shimresult, message) = translate_error(&e);
            // Move the message CString into the ShimSession, and its corresponding pointer into the raw
            // session so that C code can consume it.
            shim_session.message_cstring = message;
            raw_session.message = shim_session.message_cstring.as_ptr();
            shimresult
        }
    };

    // Release the raw pointers again
    let _ = Box::into_raw(shim_session);
    let _ = Box::into_raw(raw_session);

    returncode
}

#[no_mangle]
pub extern "C" fn free_challenge_response_session(
    session: *mut ShimRawChallengeResponseSession,
) -> () {
    // Just re-box the session and let Rust drop it all automatically.
    let raw_session = unsafe { Box::from_raw(session) };
    let _ =
        unsafe { Box::from_raw(raw_session.session_wrapper as *mut ShimChallengeResponseSession) };
}

// This function is used when there is an error while attempting to create the session - either because the
// ChallengeResponseBuilder::build() method call failed, or because ChallengeResponse::new_session() failed.
// In either case, we stub out an empty session containing just the error message.
fn stub_session_from_error(
    e: &Error,
    out_session: *mut *mut ShimRawChallengeResponseSession,
) -> ShimResult {
    // Get the error code and message by matching on the error type
    let (returncode, message) = translate_error(e);

    // Create a degenerate/stub session object to represent the failure to establish the session. Most
    // values are none/empty degnerate (but safe) placeholders.
    let shim_session = ShimChallengeResponseSession {
        client: Box::new(None),
        session_url_cstring: CString::new("").unwrap(),
        nonce_vec: Vec::new(),
        accept_type_cstring_vec: Vec::new(),
        accept_type_ptr_vec: Vec::new(),
        attestation_result_cstring: CString::new("").unwrap(),
        // This is the only meaningful field, because we have gleaned an error message.
        message_cstring: message,
    };

    // Wrap to C-compatible structure
    let raw_shim_session = Box::new(ShimRawChallengeResponseSession {
        session_url: shim_session.session_url_cstring.as_ptr(),
        nonce_size: shim_session.nonce_vec.len(),
        nonce: shim_session.nonce_vec.as_ptr(),
        accept_type_count: shim_session.accept_type_ptr_vec.len(),
        accept_type_list: shim_session.accept_type_ptr_vec.as_ptr(),
        attestation_result: std::ptr::null(),
        message: shim_session.message_cstring.as_ptr(),
        // Use Box::into_raw() to "release" the Rust memory so that the pointers all remain valid.
        session_wrapper: Box::into_raw(Box::new(shim_session)) as *mut c_void,
    });

    // Finally, use Box::into_raw() again for the raw session, so that Rust doesn't dispose it when it
    // drops out of scope.
    // C world will pass this pointer back to us in free_challenge_response_session(), at which point
    // we do Box::from_raw() to bring the memory back under Rust management.
    let session_ptr = Box::into_raw(raw_shim_session);
    unsafe { *out_session = session_ptr };

    returncode
}

// Map a rust client Error variant to a pair of C-compatible ShimResult enum value plus error message as
// CString object.
fn translate_error(e: &Error) -> (ShimResult, CString) {
    match e {
        Error::ConfigError(s) => (ShimResult::ConfigError, CString::new(s.clone()).unwrap()),
        Error::ApiError(s) => (ShimResult::ApiError, CString::new(s.clone()).unwrap()),
        Error::CallbackError(s) => (ShimResult::CallbackError, CString::new(s.clone()).unwrap()),
        Error::NotImplementedError(s) => (
            ShimResult::NotImplementedError,
            CString::new(s.clone()).unwrap(),
        ),
    }
}
