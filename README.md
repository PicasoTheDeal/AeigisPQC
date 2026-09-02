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

### 3. Quantum-Safe Authentication & Identity Verification (ML-DSA)

Before trust is granted, the initiator signs the key axchange bundle using an ML-DSA-65 (Dilithium) signature:

  + The private signing key signs the hybrid public key bundle.

  + The receiver executes `verify()` though `liboqs`. If the signature fails or was tampered with in transit, the handshake aborts immediately.

### 4. Hybrid Encapsulation and Decapsulation

```text
Peer Combined PubKey: [ X25519 PubKey (32B) || ML-KEM-768 PubKey (1184B) ]
                          │                         │
        ┌─────────────────┴─┐                     ┌─┴─────────────────┐
        │  X25519 ECDH      │                     │ ML-KEM-768        │
        │  Derivation       │                     │ Encapsulation     │
        └─────────┬─────────┘                     └─────────┬─────────┘
                  │                                         │
                  ▼                                         ▼
        Shared Secret 1 (32B)                     Shared Secret 2 (32B)
                  │                                         │
                  └──────────────────┬──────────────────────┘
                                     ▼
                    [ Secret 1 (32B) || Secret 2 (32B) ]
                                     │
                                     ▼
                              HKDF-SHA256 Extract
                                     │
                                     ▼
                          Derived 256-bit Session Key
```

### 5. HKDF Key Combiner (SNDL Defense)

The engine joins the two secrets into a 64-byte buffer and passes it through HKDF-SHA256(`EVP_PKEY_derive` in OpenSSL):

    SessionKey = HKDF-Extract-Expand(Secret X25519 || Secret ML-KEM-768)

If an adversary captures traffic and later breaks X25519 via Shor's algorithm on a quantum computer, the ML-KEM component preserves confidentiality. If ML-KEM suffers a mathematical breakthrough, X25519 maintains classical security.

## Source Code Files and Structural Responsiblities (`/include`, `/src`)

### 1. `include/aegis/common.hpp` (Shared Types & Structs)

Defines memory layout, security level enumerations, and fixed byte structures shared across all framework modules.

  + `enum class SecurityLevel`: Defines `NIST_LEVEL_1`, `NIST_LEVEL_3`, `NIST_LEVEL_5`.

  + `struct HybridPublicKey`: Byte buffer storing `x25519_pub` and `mlkem_pub`.

  + `struct HybridCiphertext`: Encapsulated quantum ciphertext and classical public key payload.

### 2. `include/aegis/crypto_interface.hpp` (Core Abstraction Layer)

Exposes pure virtual C++ interfaces for crypto primitives, isolating application logic from underlying vendor libraries.

  + `class IKemEngine`: Virtual functions for `generate_keypair()`, `encapsulate()` and `decapsulate()`.

  + `class ISignatureEngine`: Virtual functions for `generate_keypair()`, `sign()`, and `verify()`.

### 3. `src/crypto/hybrid_kem.cpp` (Dual Key Exchange Implementation)

Implements `IKemEngine` using OpenSSL 3.x for classical primitives and `liboqs` for post-quantum algorithms.

  + `generate_keypair()`: Calls `EVP_PKEY_keygen()` gor X25519 and OQS_KEM_keypair()` for ML-KEM.

  + `encapsulate()`: Perform ECDH vector derivation alongside `OQS_KEM_encaps()`.

  + `decapsulation()`: Decrypts both ciphertext streams and derives the final symmetric session key using HKDF-SHA256.

### 4. `src/crypto/mldsa_signer.cpp` (Post-Quantum Signatures)

Implements`ISignatureEngine` wrapping NIST FIPS 204 (ML-DSA / Dilithium).

  + `sign()`: Generates quantum-safe digital signatures for arbitary message buffers using `OQS_SIG_sign()`.

  + `verify()`: Validates message signatures against peer public keys via `OQS_SIG_verify()`.

### 5. `src/policy/policy_manager.cpp` (Crypto-Agility Engine)

Represents cryptographic engines dynamically based on system policy or negotiation parameters.

  + `CryptoAgilityEngine::create_kem_engine()`: Returns a `std::unique_ptr<IKemEngine>` configured for specified NIST security targets.

### 6. `src/session/aegis_session.cpp` (High-Level Protocol State Machine)

Manages the end-to-end handshake execution flow between endpoints.

  + `AegisSession`: Handles initialization, public key exchange, signature verification, shared secret derivation, and transition to AES-256-GCM symmetric transport encryption.

7. `src/main.cpp` (Integration Driver & Benchmark Utility)

Executable demonstration running key exchange, signature verification, HKDF derivation, and payload encryption cycles.

## Build Pipeline & Run

### Building AegisPQC

```bash
# 1. Generate CMake build directory
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release

# 2. Compile binaries and link against liboqs and OpenSSL
cmake --build build -j$(nproc)

# 3. Execute demo driver
./build/aegis_demo
```

## System Requirements & Dependencies

```bash
# Arch Linux

sudo pacman -S base-devel cmake clang openssl liboqs

# Debian / Ubuntu (22.04+)

sudo apt update && sudo apt install -y build-essential cmake clang libssl-dev liboqs-dev
```