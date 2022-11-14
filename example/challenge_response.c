// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "veraison_client.h"

int main(int argc, char *argv[])
{
    veraison_challenge_response_session_t session = {0};
    const unsigned char my_nonce[] = {0x01, 0x02, 0x03};
    veraison_status_t status;

    status = veraison_challenge_response_new_session(
        &session,
        "https://veraison.example.com/challenge_response",
        sizeof(my_nonce),
        my_nonce);

    printf("Hello, Veraison!\n");

    veraison_challenge_response_free_session(&session);
    
    printf("Done\n");
}
