#ifndef AEGIS_C_API_H
#define AEGIS_C_API_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AEGIS_SUCCESS = 0,
    AEGIS_ERROR_NULL_POINTER = -1,
    AEGIS_ERROR_INVALID_ARGUMENT = -2,
    AEGIS_ERROR_LOGIC = -3,
    AEGIS_ERROR_RUNTIME = -4,
    AEGIS_ERROR_BUFFER_TOO_SMALL = -5,
    AEGIS_ERROR_UNKNOWN = -99
} aegis_status_t;

typedef enum {
    AEGIS_SEC_LEVEL_NIST_3 = 3
} aegis_c_security_level_t;

typedef struct aegis_session_handle aegis_session_handle_t;

aegis_status_t aegis_session_create(aegis_c_security_level_t level, aegis_session_handle_t** out_handle);
void aegis_session_destroy(aegis_session_handle_t* handle);

aegis_status_t aegis_session_initialize_identity(aegis_session_handle_t* handle);

aegis_status_t aegis_session_export_public_key_bundle(
    const aegis_session_handle_t* handle,
    uint8_t* out_buf,
    size_t buf_cap,
    size_t* out_len
);

aegis_status_t aegis_session_export_sig_public_key(
    const aegis_session_handle_t* handle,
    uint8_t* out_buf,
    size_t buf_cap,
    size_t* out_len
);

aegis_status_t aegis_session_sign_payload(
    const aegis_session_handle_t* handle,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* out_sig,
    size_t sig_cap,
    size_t* out_sig_len
);

aegis_status_t aegis_session_process_peer_bundle(
    aegis_session_handle_t* handle,
    const uint8_t* peer_bundle,
    size_t bundle_len,
    const uint8_t* peer_sig,
    size_t sig_len,
    const uint8_t* peer_sig_pubkey,
    size_t pubkey_len,
    uint8_t* out_ciphertext,
    size_t ct_cap,
    size_t* out_ct_len
);

aegis_status_t aegis_session_finalize_handshake(
    aegis_session_handle_t* handle,
    const uint8_t* ciphertext,
    size_t ct_len
);

aegis_status_t aegis_session_encrypt_record(
    const aegis_session_handle_t* handle,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* out_iv,
    size_t iv_cap,
    uint8_t* out_ciphertext,
    size_t ct_cap,
    size_t* out_ct_len,
    uint8_t* out_tag,
    size_t tag_cap
);

aegis_status_t aegis_session_decrypt_record(
    const aegis_session_handle_t* handle,
    const uint8_t* iv,
    size_t iv_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    size_t tag_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* out_plaintext,
    size_t plaintext_cap,
    size_t* out_plaintext_len
);

#ifdef __cplusplus
}
#endif

#endif // AEGIS_C_API_H