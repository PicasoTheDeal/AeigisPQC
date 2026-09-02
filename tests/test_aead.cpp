#include <catch2/catch_test_macros.hpp>
#include "aegis/aead.hpp"
#include "aegis/aegis_session.hpp"

TEST_CASE("AES-256-GCM Direct Encrypt and Decrypt", "[crypto][aead]") {
    std::vector<uint8_t> key(32, 0x42);
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'A', 'E', 'G', 'I', 'S'};
    std::vector<uint8_t> aad = {'a', 'd', 'd', 'i', 't', 'i', 'o', 'n', 'a', 'l'};

    SECTION("Successful Encryption and Decryption") {
        auto res = aegis::crypto::aead_encrypt(key, plaintext, aad);
        REQUIRE(res.iv.size() == 12);
        REQUIRE(res.tag.size() == 16);
        REQUIRE(res.ciphertext.size() == plaintext.size());

        auto decrypted = aegis::crypto::aead_decrypt(key, res.iv, res.ciphertext, res.tag, aad);
        REQUIRE(std::vector<uint8_t>(decrypted.begin(), decrypted.end()) == plaintext);
    }

    SECTION("Tampered Ciphertext Fails Decryption") {
        auto res = aegis::crypto::aead_encrypt(key, plaintext, aad);
        res.ciphertext[0] ^= 0xFF; // Corrupt ciphertext byte

        REQUIRE_THROWS_AS(
            aegis::crypto::aead_decrypt(key, res.iv, res.ciphertext, res.tag, aad),
            std::runtime_error
        );
    }

    SECTION("Tampered Tag Fails Decryption") {
        auto res = aegis::crypto::aead_encrypt(key, plaintext, aad);
        res.tag[0] ^= 0xFF; // Corrupt auth tag byte

        REQUIRE_THROWS_AS(
            aegis::crypto::aead_decrypt(key, res.iv, res.ciphertext, res.tag, aad),
            std::runtime_error
        );
    }

    SECTION("Mismatched AAD Fails Decryption") {
        auto res = aegis::crypto::aead_encrypt(key, plaintext, aad);
        std::vector<uint8_t> bad_aad = {'b', 'a', 'd', '_', 'a', 'a', 'd'};

        REQUIRE_THROWS_AS(
            aegis::crypto::aead_decrypt(key, res.iv, res.ciphertext, res.tag, bad_aad),
            std::runtime_error
        );
    }
}

TEST_CASE("Session Record Layer Encryption/Decryption Flow", "[session][aead]") {
    aegis::session::aegis_session alice(aegis::security_level::nist_level_3);
    aegis::session::aegis_session bob(aegis::security_level::nist_level_3);

    alice.initialize_identity();
    bob.initialize_identity();

    auto alice_pub = alice.export_public_key_bundle();
    auto alice_sig_pub = alice.export_sig_public_key();
    auto alice_sig = alice.sign_payload(alice_pub);

    auto enc_secret = bob.process_peer_bundle(alice_pub, alice_sig, alice_sig_pub);
    alice.finalize_handshake(enc_secret.ciphertext);

    REQUIRE(alice.get_state() == aegis::session::session_state::handshake_complete);
    REQUIRE(bob.get_state() == aegis::session::session_state::handshake_complete);

    std::vector<uint8_t> payload = {'S', 'e', 'c', 'r', 'e', 't', ' ', 'D', 'a', 't', 'a'};
    std::vector<uint8_t> aad = {'c', 'h', 'a', 'n', 'n', 'e', 'l', '_', '1'};

    // Alice encrypts record using HKDF session key
    auto record = alice.encrypt_record(payload, aad);

    // Bob decrypts record using derived HKDF session key
    auto decrypted = bob.decrypt_record(record.iv, record.ciphertext, record.tag, aad);
    REQUIRE(std::vector<uint8_t>(decrypted.begin(), decrypted.end()) == payload);
}