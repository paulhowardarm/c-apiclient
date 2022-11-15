// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "veraison_client.h"

int main(int argc, char *argv[])
{
    veraison_challenge_response_session_t session = {0};
    const unsigned char my_nonce[] = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef};
    const unsigned char my_evidence[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    veraison_status_t status;
    size_t i;

    status = veraison_challenge_response_new_session(
        &session,
        "http://127.0.0.1:8080/challenge-response/v1/",
        sizeof(my_nonce),
        my_nonce);

    if (status != VERAISON_STATUS_OK)
    {
        printf("Failed to allocate Veraison client session.\n");
        goto cleanup;
    }

    printf("Opened new Veraison client session at %s\n", session.session_url);
    printf("Number of media types accepted: %d\n", (int) session.accept_count);
    for (i = 0; i < session.accept_count; i++)
    {
        printf("    %s\n", session.accept_types[i]);
    }
    printf("Nonce size: %d bytes", (int) session.nonce_size);
    printf("Nonce: [");
    for (i = 0; i < session.nonce_size; i++)
    {
        if (i > 0)
        {
            printf(", ");
        }
        printf("0x%x", session.nonce[i]);
    }
    printf("]\n");

    if (session.accept_count == 0)
    {
        printf("There are no accepted media types, hence not supplying evidence.\n");
        goto cleanup;
    }

    printf("Supplying evidence to server.\n");

    status = veraison_challenge_response_supply_evidence(
        &session,
        session.accept_types[0],
        sizeof(my_evidence),
        my_evidence);

cleanup:
    veraison_challenge_response_free_session(&session);
    printf("Done!\n");
    return (int)status;
}
