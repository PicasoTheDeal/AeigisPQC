#include "aegis/policy_manager.hpp"

namespace aegis::crypto {
std::unique_ptr<ikem_engine> create_hybrid_kem();
std::unique_ptr<isignature_engine> create_mldsa_signer();
}

namespace aegis::policy {

crypto_agility_engine::crypto_agility_engine(security_level level) noexcept
    : current_level_(level) {}

std::unique_ptr<crypto::ikem_engine> crypto_agility_engine::create_kem_engine() const {
    switch (current_level_) {
        case security_level::nist_level_3:
        default:
            return crypto::create_hybrid_kem();
    }
}

std::unique_ptr<crypto::isignature_engine> crypto_agility_engine::create_signature_engine() const {
    switch (current_level_) {
        case security_level::nist_level_3:
        default:
            return crypto::create_mldsa_signer();
    }
}

void crypto_agility_engine::set_security_level(security_level level) noexcept {
    current_level_ = level;
}

security_level crypto_agility_engine::get_security_level() const noexcept {
    return current_level_;
}

} // namespace aegis::policy