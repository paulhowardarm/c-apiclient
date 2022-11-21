// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#include "veraison_client.h"
#include "bindings.h"

veraison_status_t veraison_challenge_response_new_session(
    veraison_challenge_response_session_t *session,
    const char *const base_url,
    size_t nonce_size,
    const unsigned char *const nonce)
{
    uint32_t status = 0;
    ShimRawChallengeResponseSession *session_ptr = NULL;
    status = open_challenge_response_session(base_url, nonce_size, nonce, &session_ptr);

    if (status == 0)
    {
        session->reserved = (void *)session_ptr;
        session->session_url = session_ptr->session_url;
        session->nonce_size = session_ptr->nonce_size;
        session->nonce = session_ptr->nonce;
        session->accept_count = session_ptr->accept_type_count;
        session->accept_types = session_ptr->accept_type_list;
        session->attestation_result = NULL;
        return VERAISON_STATUS_OK;
    }
    else
    {
        /* TODO(paulhowardarm) mapping of failing codes from the Rust wrapper to C. */
        return 1;
    }
}

veraison_status_t veraison_challenge_response_supply_evidence(
    veraison_challenge_response_session_t *session,
    const char *const media_type,
    size_t evidence_size,
    const unsigned char *const evidence)
{
    uint32_t status = 0;
    ShimRawChallengeResponseSession *session_ptr = (ShimRawChallengeResponseSession *)session->reserved;

    status = challenge_response(session_ptr, evidence_size, evidence, media_type);

    if (status == 0)
    {
        session->attestation_result = session_ptr->attestation_result;
        return VERAISON_STATUS_OK;
    }
    else
    {
        /* TODO(paulhowardarm) mapping of failing codes from the Rust wrapper to C. */
        return 1;
    }
}

void veraison_challenge_response_free_session(veraison_challenge_response_session_t *session)
{
    if (session != NULL && session->reserved != NULL)
    {
        free_challenge_response_session((ShimRawChallengeResponseSession *)session->reserved);
        session->reserved = NULL;
        session->session_url = NULL;
        session->nonce_size = 0;
        session->nonce = NULL;
        session->accept_count = 0;
        session->accept_types = NULL;
        session->attestation_result = NULL;
    }
}
