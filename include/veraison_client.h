// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

/**
 * \file veraison_client.h
 * \brief C client interface to an attestation verification service based on Veraison.
 */

#ifndef VERAISON_CLIENT_H
#define VERAISON_CLIENT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Common result status for operations.
 */
typedef int veraison_status_t;

/**
 * This structure encpasulates the details of a challenge/response API session.
 */
typedef struct _veraison_challenge_response_session_t {
    const char *const session_url;
    size_t nonce_size;
    const unsigned char *const nonce;
    size_t accept_count;
    const char *const *const accept_types;
} veraison_challenge_response_session_t;

/**
 * Create and initialize a new challenge/response session.
 */
veraison_status_t veraison_challenge_response_new_session(
    veraison_challenge_response_session_t *session,
    const char *const base_url,
    size_t nonce_size,
    const unsigned char *const nonce
);

/**
 * Supply the verification evidence for a challenge/response session.
 */
veraison_status_t veraison_challenge_response_supply_evidence(
    veraison_challenge_response_session_t *session,
    const char *const media_type,
    size_t evidence_size,
    const unsigned char *const evidence
);

/**
 * Completely dispose of all memory and resources associated with a challenge/response session.
 */
void veraison_challenge_response_free_session(veraison_challenge_response_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* VERAISON_CLIENT_H */
