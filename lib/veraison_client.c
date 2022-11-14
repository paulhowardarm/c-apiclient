// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#include "veraison_client.h"

veraison_status_t veraison_challenge_response_new_session(
    veraison_challenge_response_session_t *session,
    const char *const base_url,
    size_t nonce_size,
    const unsigned char *const nonce
)
{
    return 0;
}

veraison_status_t veraison_challenge_response_supply_evidence(
    veraison_challenge_response_session_t *session,
    const char *const media_type,
    size_t evidence_size,
    const unsigned char *const evidence
)
{
    return 0;
}

void veraison_challenge_response_free_session(veraison_challenge_response_session_t *session)
{
}
