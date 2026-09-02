#include "aegis/aegis_session.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <string_view>

void print_hex(std::string_view label, std::span<const uint8_t> data) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < std::min(data.size(), size_t{16}); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << "...\n" << std::dec;
}

int main() {
    try {
        std::cout << "--- starting aegispqc session handshake ---\n\n";

        // 1. initialize alice and bob sessions
        aegis::session::aegis_session alice(aegis::security_level::nist_level_3);
        aegis::session::aegis_session bob(aegis::security_level::nist_level_3);

        alice.initialize_identity();
        bob.initialize_identity();

        std::cout << "[1] identities initialized for alice and bob\n";

        // 2. alice exports public key bundle & signature key, then signs the bundle
        auto alice_bundle = alice.export_public_key_bundle();
        auto alice_sig_pub = alice.export_sig_public_key();
        auto alice_sig = alice.sign_payload(alice_bundle);

        print_hex("[2] alice public key bundle", alice_bundle);
        print_hex("[2] alice mldsa-65 signature", alice_sig);

        // 3. bob verifies alice signature, encapsulates shared key
        auto encapsulated = bob.process_peer_bundle(alice_bundle, alice_sig, alice_sig_pub);
        std::cout << "[3] bob verified signature and encapsulated shared secret\n";

        // 4. alice receives bob ciphertext and decapsulates
        alice.finalize_handshake(encapsulated.ciphertext);
        std::cout << "[4] alice decapsulated ciphertext\n\n";

        // 5. verify derived session keys match
        auto alice_key = alice.get_session_key();
        auto bob_key = bob.get_session_key();

        print_hex("alice derived session key", alice_key);
        print_hex("bob derived session key  ", bob_key);

        if (std::equal(alice_key.begin(), alice_key.end(), bob_key.begin(), bob_key.end())) {
            std::cout << "\n[success] hkdf hybrid session keys match perfectly!\n";
        } else {
            std::cout << "\n[failure] session keys do not match!\n";
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "fatal error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}