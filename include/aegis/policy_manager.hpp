#pragma once
#include "crypto_interface.hpp"
#include <memory>

namespace aegis::policy {

class crypto_agility_engine {
private:
    security_level current_level_;

public:
    explicit crypto_agility_engine(security_level level = security_level::nist_level_3) noexcept;

    [[nodiscard]] std::unique_ptr<crypto::ikem_engine> create_kem_engine() const;
    [[nodiscard]] std::unique_ptr<crypto::isignature_engine> create_signature_engine() const;

    void set_security_level(security_level level) noexcept;
    [[nodiscard]] security_level get_security_level() const noexcept;
};

} // namespace aegis::policy