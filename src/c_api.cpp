#include "aegis/c_api.h"
#include "aegis/aegis_session.hpp"
#include <exception>
#include <new>
#include <cstring>
#include <algorithm>

struct aegis_session_handle {
    aegis::session::aegis_session impl;
    explicit aegis_session_handle(aegis::security_level level) : impl(level) {}
};

#define C_ABI_BEGIN try {
#define C_ABI_END \
    return AEGIS_SUCCESS; \
    } catch (const std::invalid_argument&) { \
        return AEGIS_ERROR_INVALID_ARGUMENT; \
    } catch (const std::logic_error&) { \
        return AEGIS_ERROR_LOGIC; \
    } catch (const std::runtime_error&) { \
        return AEGIS_ERROR_RUNTIME; \
    } catch (const std::bad_alloc&) { \
        return AEGIS_ERROR_RUNTIME; \
    } catch (...) { \
        return AEGIS_ERROR_UNKNOWN; \
    }

extern "C" {

aegis_status_t aegis_session_create(aegis_c_security_level_t level, aegis_session_handle_t** out_handle) {
    if (!out_handle) return AEGIS_ERROR_NULL_POINTER;
    C_ABI_BEGIN
    auto sec_level = static_cast<aegis::security_level>(level);
    *out_handle = new aegis_session_handle(sec_level);
    C_ABI_END
}

void aegis_session_destroy(aegis_session_handle_t* handle) {
    delete handle;
}

aegis_status_t aegis_session_initialize_identity(aegis_session_handle_t* handle) {
    if (!handle) return AEGIS_ERROR_NULL_POINTER;
    C_ABI_BEGIN
    handle->impl.initialize_identity();
    C_ABI_END
}

aegis_status_t aegis_session_export_public_key_bundle(
    const aegis_session_handle_t* handle,
    uint8_t* out_buf,
    size_t buf_cap,
    size_t* out_len
) {
    if (!handle || !out_len) return AEGIS_ERROR_NULL_POINTER;
    C_ABI_BEGIN
    auto bundle = handle->impl.export_public_key_bundle();
    *out_len = bundle.size();
    if (!out_buf) return AEGIS_SUCCESS; // Length query
    if (buf_cap < bundle.size()) return AEGIS_ERROR_BUFFER_TOO_SMALL;
    std::memcpy(out_buf, bundle.data(), bundle.size());
    C_ABI_END
}

aegis_status_t aegis_session_export_sig_public_key(
    const aegis_session_handle_t* handle,
    uint8_t* out_buf,
    size_t buf_cap,
    size_t* out_len
) {
    if (!handle || !out_len) return AEGIS_ERROR_NULL_POINTER;
    C_ABI_BEGIN
    auto key = handle->impl.export_sig_public_key();
    *out_len = key.size();
    if (!out_buf) return AEGIS_SUCCESS;
    if (buf_cap < key.size()) return AEGIS_ERROR_BUFFER_TOO_SMALL;
    std::memcpy(out_buf, key.data(), key.size());
    C_ABI_END
}

aegis_status_t aegis_session_sign_payload(
    const aegis_session_handle_t* handle,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* out_sig,
    size_t sig_cap,
    size_t* out_sig_len
) {
    if (!handle || (!payload && payload_len > 0) || !out_sig_len) return AEGIS_ERROR_NULL_POINTER;
    C_ABI_BEGIN
    auto sig = handle->impl.sign_payload({payload, payload_len});
    *out_sig_len = sig.size();
    if (!out_sig) return AEGIS_SUCCESS;
    if (sig_cap < sig.size()) return AEGIS_ERROR_BUFFER_TOO_SMALL;
    std::memcpy(out_sig, sig.data(), sig.size());
    C_ABI_END
}

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
) {
    if (!handle || !peer_bundle || !peer_sig || !peer_sig_pubkey || !out_ct_len) return AEGIS_ERROR_NULL_POINTER;
    C_ABI_BEGIN
    auto enc = handle->impl.process_peer_bundle(
        {peer_bundle, bundle_len},
        {peer_sig, sig_len},
        {peer_sig_pubkey, pubkey_len}
    );
    *out_ct_len = enc.ciphertext.size();
    if (!out_ciphertext) return AEGIS_SUCCESS;
    if (ct_cap < enc.ciphertext.size()) return AEGIS_ERROR_BUFFER_TOO_SMALL;
    std::memcpy(out_ciphertext, enc.ciphertext.data(), enc.ciphertext.size());
    C_ABI_END
}

aegis_status_t aegis_session_finalize_handshake(
    aegis_session_handle_t* handle,
    const uint8_t* ciphertext,
    size_t ct_len
) {
    if (!handle || (!ciphertext && ct_len > 0)) return AEGIS_ERROR_NULL_POINTER;
    C_ABI_BEGIN
    handle->impl.finalize_handshake({ciphertext, ct_len});
    C_ABI_END
}

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
) {
    if (!handle || (!plaintext && plaintext_len > 0) || !out_iv || !out_ciphertext || !out_ct_len || !out_tag) {
        return AEGIS_ERROR_NULL_POINTER;
    }
    C_ABI_BEGIN
    auto res = handle->impl.encrypt_record({plaintext, plaintext_len}, {aad, aad_len});
    if (iv_cap < res.iv.size() || tag_cap < res.tag.size() || ct_cap < res.ciphertext.size()) {
        return AEGIS_ERROR_BUFFER_TOO_SMALL;
    }
    *out_ct_len = res.ciphertext.size();
    std::memcpy(out_iv, res.iv.data(), res.iv.size());
    std::memcpy(out_tag, res.tag.data(), res.tag.size());
    std::memcpy(out_ciphertext, res.ciphertext.data(), res.ciphertext.size());
    C_ABI_END
}

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
) {
    if (!handle || !iv || (!ciphertext && ciphertext_len > 0) || !tag || !out_plaintext_len) {
        return AEGIS_ERROR_NULL_POINTER;
    }
    C_ABI_BEGIN
    auto pt = handle->impl.decrypt_record({iv, iv_len}, {ciphertext, ciphertext_len}, {tag, tag_len}, {aad, aad_len});
    *out_plaintext_len = pt.size();
    if (!out_plaintext) return AEGIS_SUCCESS;
    if (plaintext_cap < pt.size()) return AEGIS_ERROR_BUFFER_TOO_SMALL;
    std::memcpy(out_plaintext, pt.data(), pt.size());
    C_ABI_END
}

} // extern "C"