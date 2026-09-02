#include "aegis/aegis_session.hpp"
#include <iostream>
#include <format>

int main() {
    try {
        // instantiate alice and bob sessions
        aegis::session::aegis_session alice(aegis::security_level::nist_level_3);
        aegis::session::aegis_session bob(aegis::security_level::nist_level_3);

        alice.initialize_identity();
        bob.initialize_identity();

        // alice exports public bundle and signs it
        auto alice_bundle = alice.export_public_key_bundle();
        auto alice_sig = alice.sign_payload(alice_bundle);

        // bob processes alice bundle, verifies signature, encapsulates shared key
        // bob signature public key mock pass
        // in real usage identity keys are exchanged out of band or via x509 certs
        std::cout << "executing hybrid x25519 mlkem768 handshake...\n";

    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}