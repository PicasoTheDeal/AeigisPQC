#include <catch2/catch_test_macros.hpp>
#include "aegis/aegis_session.hpp"

TEST_CASE("Session state machine constraints", "[session][state]") {
    aegis::session::aegis_session session(aegis::security_level::nist_level_3);

    SECTION("Uninitialized session blocks key export") {
        REQUIRE_THROWS_AS(session.export_public_key_bundle(), std::logic_error);
        REQUIRE_THROWS_AS(session.export_sig_public_key(), std::logic_error);
    }

    SECTION("Uninitialized session blocks decapsulation") {
        std::vector<uint8_t> dummy_ct(100, 0x00);
        REQUIRE_THROWS_AS(session.finalize_handshake(dummy_ct), std::logic_error);
    }

    SECTION("Initialization unlocks export functions") {
        session.initialize_identity();
        REQUIRE(session.get_state() == aegis::session::session_state::key_generated);
        REQUIRE_NOTHROW(session.export_public_key_bundle());
    }
}

TEST_CASE("Session peer verification fail-safe", "[session][security]") {
    aegis::session::aegis_session alice(aegis::security_level::nist_level_3);
    aegis::session::aegis_session bob(aegis::security_level::nist_level_3);

    alice.initialize_identity();
    bob.initialize_identity();

    auto alice_bundle = alice.export_public_key_bundle();
    auto alice_sig_pub = alice.export_sig_public_key();
    auto alice_sig = alice.sign_payload(alice_bundle);

    SECTION("Tampered signature transitions session state to failed") {
        alice_sig[0] ^= 0xFF; // mutate signature byte
        REQUIRE_THROWS_AS(bob.process_peer_bundle(alice_bundle, alice_sig, alice_sig_pub), std::runtime_error);
        REQUIRE(bob.get_state() == aegis::session::session_state::failed);
    }
}