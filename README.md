# AegisPQC 

## Diagram

    ┌─────────────────────────────────────────────────────────────────────────┐
    │                    APPLICATION / HOST LAYER (C++20)                     │
    │                                                                         │
    │  ┌───────────────────────┐                  ┌────────────────────────┐  │
    │  │     Client/Server     │ ───────────────► │   AegisSession Engine  │  │
    │  │   Application Logic   │                  │  (Handshake State Machine)│
    │  └───────────────────────┘                  └───────────┬────────────┘  │
    └─────────────────────────────────────────────────────────┼───────────────┘
                                                              │ 
                                       Config / Policy Params │ (NIST Level Selection)
                                                              ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                       AEGISPQC FRAMEWORK CORE                           │
    │                                                                         │
    │  ┌───────────────────────────────────────────────────────────────────┐  │
    │  │                   CryptoAgilityEngine / PolicyManager             │  │
    │  └─────────────────────────────────┬─────────────────────────────────┘  │
    │                                    │                                    │
    │                 ┌──────────────────┴──────────────────┐                 │
    │                 ▼                                     ▼                 │
    │  ┌───────────────────────────────┐   ┌───────────────────────────────┐  │
    │  │    Hybrid KEM Engine          │   │  Quantum Signature Engine     │  │
    │  │  (X25519 + ML-KEM-768)        │   │  (ML-DSA-65 / Dilithium)      │  │
    │  └──────────────┬────────────────┘   └──────────────┬────────────────┘  │
    │                 │                                   │                   │
    │                 │ Derives                           │ Validates         │
    │                 ▼                                   ▼                   │
    │  ┌───────────────────────────────┐   ┌───────────────────────────────┐  │
    │  │    HKDF-SHA256 Combiner       │   │  Identity & Public Key Trust  │  │
    │  │ (S_classical || S_pqc -> Key) │   │  Verification Engine          │  │
    │  └──────────────┬────────────────┘   └───────────────────────────────┘  │
    └─────────────────┼───────────────────────────────────────────────────────┘
                      │
                      ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                  PRIMITIVE LIBRARIES & HARDWARE LAYER                   │
    │                                                                         │
    │  ┌───────────────────────────────┐   ┌───────────────────────────────┐  │
    │  │    OpenSSL 3.x (Libcrypto)    │   │      liboqs (Open Quantum)    │  │
    │  │     - X25519 / HKDF / AES     │   │     - ML-KEM (Kyber)          │  │
    │  │                               │   │     - ML-DSA (Dilithium)      │  │
    │  └───────────────────────────────┘   └───────────────────────────────┘  │
    └─────────────────────────────────────────────────────────────────────────┘


## Logic Flow and Architecture

    ### 1. Security Level and Policy Selection

        When an application establishes a secure channel, `AegisSession` queries `CryptoAgilityEngine` with a configured security target
        (e.g. NIST_LEVEL_3). `PolicyManager` dynamically instantiates the appropriate primitives without forcing application code refractoring.

    ### 2. Dual Key Pair Generation (Client Hybrid Identity)

        To prevent single-algorithm points of failure, key generation creates a unified hybrid payload containing classical and posat-quantum keys:

            + Classical Key Generation: The engine uses OpenSSL `EVP_PKEY` to generate a standard X25519 Elliptic Curve Diffle-Hellman (ECDH) keypair.

            + Post-Quantum Key Generation: The engine uses `liboqs` to generate an ML-KEM-768 (Kyber) latice keypair.

            + Payload Packaging: Classical public key (32 bytes) and post-quantum public key (1184 bytes) are packed into a single byte stream. 