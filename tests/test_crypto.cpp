#include <catch2/catch_test_macros.hpp>
#include "aegis/policy_manager.hpp"

TEST_CASE("Hybrid KEM engine boundary validation", "[crypto][kem]") {
    aegis::policy::crypto_agility_engine agility(aegis::security_level::nist_level_3);
    auto kem = agility.create_kem_engine();

    SECTION("Keypair length correctness") {
        auto pair = kem->generate_keypair();
        REQUIRE(pair.public_key.size() == (aegis::x25519_pub_len + aegis::mlkem768_pub_len));
        REQUIRE(pair.secret_key.size() == (aegis::x25519_priv_len + aegis::mlkem768_priv_len));
    }

    SECTION("Reject malformed public keys") {
        std::vector<uint8_t> invalid_pubkey(100, 0xFF); // incorrect length
        REQUIRE_THROWS_AS(kem->encapsulate(invalid_pubkey), std::invalid_argument);
    }
}

TEST_CASE("ML-DSA signature verification and tampering", "[crypto][sig]") {
    aegis::policy::crypto_agility_engine agility(aegis::security_level::nist_level_3);
    auto sig_engine = agility.create_signature_engine();

    auto keys = sig_engine->generate_keypair();
    std::vector<uint8_t> msg = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto signature = sig_engine->sign(msg, keys.secret_key);
    REQUIRE_FALSE(signature.empty());

    SECTION("Valid signature passes") {
        REQUIRE(sig_engine->verify(msg, signature, keys.public_key));
    }

    SECTION("Corrupted payload fails verification") {
        auto tampered_msg = msg;
        tampered_msg[0] ^= 0xFF;
        REQUIRE_FALSE(sig_engine->verify(tampered_msg, signature, keys.public_key));
    }

    SECTION("Corrupted signature fails verification") {
        auto tampered_sig = signature;
        tampered_sig[0] ^= 0xFF;
        REQUIRE_FALSE(sig_engine->verify(msg, tampered_sig, keys.public_key));
    }
}