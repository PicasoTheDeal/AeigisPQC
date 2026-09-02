#include "aegis/aegis_session.hpp"
#include <stdexcept>

namespace aegis::session {

aegis_session::aegis_session(security_level level)
    : agility_engine_(level),
      kem_engine_(agility_engine_.create_kem_engine()),
      sig_engine_(agility_engine_.create_signature_engine()) {}

void aegis_session::initialize_identity() {
    local_kem_keys_ = kem_engine_->generate_keypair();
    local_sig_keys_ = sig_engine_->generate_keypair();
    state_ = session_state::key_generated;
}

std::vector<uint8_t> aegis_session::export_public_key_bundle() const {
    if (state_ == session_state::uninitialized) {
        throw std::logic_error("session uninitialized");
    }
    return local_kem_keys_.public_key;
}

std::vector<uint8_t> aegis_session::export_sig_public_key() const {
    if (state_ == session_state::uninitialized) {
        throw std::logic_error("session uninitialized");
    }
    return local_sig_keys_.public_key;
}

encapsulated_secret aegis_session::process_peer_bundle(std::span<const uint8_t> peer_bundle, std::span<const uint8_t> peer_sig, std::span<const uint8_t> peer_sig_pubkey) {
    if (!sig_engine_->verify(peer_bundle, peer_sig, peer_sig_pubkey)) {
        state_ = session_state::failed;
        throw std::runtime_error("peer signature verification failed");
    }

    auto secret = kem_engine_->encapsulate(peer_bundle);
    derived_session_key_ = secret.shared_secret;
    state_ = session_state::handshake_complete;
    return secret;
}

void aegis_session::finalize_handshake(std::span<const uint8_t> ciphertext) {
    if (state_ != session_state::key_generated) {
        throw std::logic_error("invalid session state for decapsulation");
    }

    derived_session_key_ = kem_engine_->decapsulate(ciphertext, local_kem_keys_.secret_key);
    state_ = session_state::handshake_complete;
}

std::vector<uint8_t> aegis_session::sign_payload(std::span<const uint8_t> payload) const {
    return sig_engine_->sign(payload, local_sig_keys_.secret_key);
}

bool aegis_session::verify_payload(std::span<const uint8_t> payload, std::span<const uint8_t> sig, std::span<const uint8_t> pubkey) const {
    return sig_engine_->verify(payload, sig, pubkey);
}

} // namespace aegis::session