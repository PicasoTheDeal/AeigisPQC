#pragma once
#include "common.hpp"
#include "crypto_interface.hpp"
#include "policy_manager.hpp"
#include "aead.hpp"
#include <memory>
#include <span>
#include <vector>

namespace aegis::session {

enum class session_state {
    uninitialized,
    key_generated,
    handshake_complete,
    failed
};

class aegis_session {
private:
    session_state state_{session_state::uninitialized};
    policy::crypto_agility_engine agility_engine_;
    std::unique_ptr<crypto::ikem_engine> kem_engine_;
    std::unique_ptr<crypto::isignature_engine> sig_engine_;

    key_pair local_kem_keys_;
    key_pair local_sig_keys_;
    secure_vector derived_session_key_;

public:
    explicit aegis_session(security_level level = security_level::nist_level_3);

    void initialize_identity();

    [[nodiscard]] std::vector<uint8_t> export_public_key_bundle() const;
    [[nodiscard]] std::vector<uint8_t> export_sig_public_key() const;

    [[nodiscard]] encapsulated_secret process_peer_bundle(
        std::span<const uint8_t> peer_bundle,
        std::span<const uint8_t> peer_sig,
        std::span<const uint8_t> peer_sig_pubkey
    );

    void finalize_handshake(std::span<const uint8_t> ciphertext);

    [[nodiscard]] std::vector<uint8_t> sign_payload(std::span<const uint8_t> payload) const;
    [[nodiscard]] bool verify_payload(
        std::span<const uint8_t> payload,
        std::span<const uint8_t> sig,
        std::span<const uint8_t> pubkey
    ) const;

    [[nodiscard]] crypto::aead_result encrypt_record(
        std::span<const uint8_t> plaintext, 
        std::span<const uint8_t> aad = {}
    ) const;

    [[nodiscard]] secure_vector decrypt_record(
        std::span<const uint8_t> iv, 
        std::span<const uint8_t> ciphertext, 
        std::span<const uint8_t> tag, 
        std::span<const uint8_t> aad = {}
    ) const;

    [[nodiscard]] session_state get_state() const noexcept { return state_; }
    [[nodiscard]] std::span<const uint8_t> get_session_key() const noexcept { return derived_session_key_; }
};

} // namespace aegis::session