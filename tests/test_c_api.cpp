#include <catch2/catch_test_macros.hpp>
#include "aegis/c_api.h"
#include <vector>

TEST_CASE("C-ABI Handshake and Encryption Lifecycle", "[ffi][c_api]") {
    aegis_session_handle_t* alice = nullptr;
    aegis_session_handle_t* bob = nullptr;

    REQUIRE(aegis_session_create(AEGIS_SEC_LEVEL_NIST_3, &alice) == AEGIS_SUCCESS);
    REQUIRE(aegis_session_create(AEGIS_SEC_LEVEL_NIST_3, &bob) == AEGIS_SUCCESS);

    REQUIRE(aegis_session_initialize_identity(alice) == AEGIS_SUCCESS);
    REQUIRE(aegis_session_initialize_identity(bob) == AEGIS_SUCCESS);

    // Query stateless buffer lengths for public keys
    size_t alice_bundle_len = 0, alice_sig_pub_len = 0;
    REQUIRE(aegis_session_export_public_key_bundle(alice, nullptr, 0, &alice_bundle_len) == AEGIS_SUCCESS);
    REQUIRE(aegis_session_export_sig_public_key(alice, nullptr, 0, &alice_sig_pub_len) == AEGIS_SUCCESS);

    std::vector<uint8_t> alice_bundle(alice_bundle_len);
    std::vector<uint8_t> alice_sig_pub(alice_sig_pub_len);

    REQUIRE(aegis_session_export_public_key_bundle(alice, alice_bundle.data(), alice_bundle.size(), &alice_bundle_len) == AEGIS_SUCCESS);
    REQUIRE(aegis_session_export_sig_public_key(alice, alice_sig_pub.data(), alice_sig_pub.size(), &alice_sig_pub_len) == AEGIS_SUCCESS);

    // Sign public key bundle
    size_t sig_len = 0;
    REQUIRE(aegis_session_sign_payload(alice, alice_bundle.data(), alice_bundle.size(), nullptr, 0, &sig_len) == AEGIS_SUCCESS);
    std::vector<uint8_t> alice_sig(sig_len);
    REQUIRE(aegis_session_sign_payload(alice, alice_bundle.data(), alice_bundle.size(), alice_sig.data(), alice_sig.size(), &sig_len) == AEGIS_SUCCESS);

    // Single-shot stateful encapsulation (allocate buffer for hybrid KEM ciphertext)
    std::vector<uint8_t> ciphertext(2048);
    size_t ct_len = 0;
    REQUIRE(aegis_session_process_peer_bundle(
        bob, alice_bundle.data(), alice_bundle.size(),
        alice_sig.data(), alice_sig.size(),
        alice_sig_pub.data(), alice_sig_pub.size(),
        ciphertext.data(), ciphertext.size(), &ct_len
    ) == AEGIS_SUCCESS);
    ciphertext.resize(ct_len);

    // Alice finalizes handshake
    REQUIRE(aegis_session_finalize_handshake(alice, ciphertext.data(), ciphertext.size()) == AEGIS_SUCCESS);

    // Record Encryption via C API
    std::vector<uint8_t> msg = {'F', 'F', 'I', '_', 'T', 'E', 'S', 'T'};
    std::vector<uint8_t> aad = {'A', 'A', 'D'};
    uint8_t iv[12], tag[16];
    std::vector<uint8_t> rec_ct(msg.size());
    size_t rec_ct_len = 0;

    REQUIRE(aegis_session_encrypt_record(
        alice, msg.data(), msg.size(), aad.data(), aad.size(),
        iv, sizeof(iv), rec_ct.data(), rec_ct.size(), &rec_ct_len, tag, sizeof(tag)
    ) == AEGIS_SUCCESS);

    // Bob decrypts record via C API
    std::vector<uint8_t> decrypted(rec_ct_len);
    size_t decrypted_len = 0;
    REQUIRE(aegis_session_decrypt_record(
        bob, iv, sizeof(iv), rec_ct.data(), rec_ct_len, tag, sizeof(tag),
        aad.data(), aad.size(), decrypted.data(), decrypted.size(), &decrypted_len
    ) == AEGIS_SUCCESS);

    REQUIRE(decrypted == msg);

    aegis_session_destroy(alice);
    aegis_session_destroy(bob);
}