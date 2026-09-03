#include "aegis/policy_manager.hpp"
#include "aegis/aead.hpp"
#include "aegis/aegis_session.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string_view>
#include <vector>

namespace bench {

// Compiler optimization barrier to prevent dead code elimination (DCE)
template <typename T>
inline void do_not_optimize(T&& value) noexcept {
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" : : "r,m"(value) : "memory");
#else
    static volatile const void* sink;
    sink = &value;
#endif
}

struct MetricResult {
    double mean_us;
    double p50_us;
    double p99_us;
    double ops_per_sec;
};

template <typename Func>
[[nodiscard]] MetricResult measure(Func&& func, size_t iterations, size_t warmup_iterations = 50) {
    // Warmup phase: Prime instruction cache and stabilize CPU frequency scaling
    for (size_t i = 0; i < warmup_iterations; ++i) {
        auto res = func();
        do_not_optimize(res);
    }

    std::vector<double> timings_us;
    timings_us.reserve(iterations);

    // Per-iteration sampling for quantile analysis
    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::steady_clock::now();
        auto res = func();
        auto end = std::chrono::steady_clock::now();
        
        do_not_optimize(res);

        std::chrono::duration<double, std::micro> elapsed = end - start;
        timings_us.push_back(elapsed.count());
    }

    std::sort(timings_us.begin(), timings_us.end());

    double total_us = std::accumulate(timings_us.begin(), timings_us.end(), 0.0);
    double mean_us = total_us / static_cast<double>(iterations);
    double p50_us = timings_us[static_cast<size_t>(iterations * 0.50)];
    double p99_us = timings_us[static_cast<size_t>(iterations * 0.99)];
    double ops_per_sec = 1'000'000.0 / mean_us;

    return MetricResult{mean_us, p50_us, p99_us, ops_per_sec};
}

void print_header(std::string_view title) {
    std::cout << "\n[" << title << "]\n"
              << std::left << std::setw(32) << " Operation"
              << std::right << std::setw(12) << "Mean (us)"
              << std::setw(12) << "p50 (us)"
              << std::setw(12) << "p99 (us)"
              << std::setw(15) << "Ops/sec" << "\n"
              << std::string(83, '-') << "\n";
}

void print_row(std::string_view name, const MetricResult& m) {
    std::cout << std::left << std::setw(32) << name
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(12) << m.mean_us
              << std::setw(12) << m.p50_us
              << std::setw(12) << m.p99_us
              << std::setprecision(1)
              << std::setw(15) << m.ops_per_sec << "\n";
}

} // namespace bench

int main() {
    std::cout << "                         AEGIS-PQC PERFORMANCE BENCHMARK                           \n";
    aegis::policy::crypto_agility_engine agility(aegis::security_level::nist_level_3);
    auto kem = agility.create_kem_engine();
    auto sig = agility.create_signature_engine();

    // 1. Hybrid KEM (X25519 + ML-KEM-768)
    bench::print_header("1. Hybrid KEM Operations (NIST Level 3)");
    auto keypair = kem->generate_keypair();
    auto enc_res = kem->encapsulate(keypair.public_key);

    bench::print_row("Keypair Generation", bench::measure([&]() { return kem->generate_keypair(); }, 500));
    bench::print_row("Encapsulation", bench::measure([&]() { return kem->encapsulate(keypair.public_key); }, 500));
    bench::print_row("Decapsulation", bench::measure([&]() { return kem->decapsulate(enc_res.ciphertext, keypair.secret_key); }, 500));

    // 2. ML-DSA Signatures
    bench::print_header("2. Digital Signature Operations (ML-DSA-65)");
    auto sig_keys = sig->generate_keypair();
    const std::vector<uint8_t> payload(256, 0x42);
    auto signature = sig->sign(payload, sig_keys.secret_key);

    bench::print_row("Keypair Generation", bench::measure([&]() { return sig->generate_keypair(); }, 200));
    bench::print_row("Payload Signing (256 B)", bench::measure([&]() { return sig->sign(payload, sig_keys.secret_key); }, 500));
    bench::print_row("Signature Verification", bench::measure([&]() { return sig->verify(payload, signature, sig_keys.public_key); }, 500));

    // 3. Symmetric AEAD (AES-256-GCM Throughput)
    bench::print_header("3. AEAD Record Layer (AES-256-GCM)");
    const std::vector<uint8_t> key(32, 0x01);
    const std::vector<uint8_t> aad(16, 0x02);
    const std::vector<uint8_t> msg_1k(1024, 0xAA);
    const std::vector<uint8_t> msg_64k(64 * 1024, 0xBB);

    auto aead_1k = bench::measure([&]() { return aegis::crypto::aead_encrypt(key, msg_1k, aad); }, 1000);
    auto aead_64k = bench::measure([&]() { return aegis::crypto::aead_encrypt(key, msg_64k, aad); }, 500);

    bench::print_row("Encrypt 1 KB Payload", aead_1k);
    bench::print_row("Encrypt 64 KB Payload", aead_64k);

    double mb_s_1k = (1024.0 / (1024.0 * 1024.0)) / (aead_1k.mean_us / 1'000'000.0);
    double mb_s_64k = ((64.0 * 1024.0) / (1024.0 * 1024.0)) / (aead_64k.mean_us / 1'000'000.0);
    std::cout << "\n  --> Throughput (1 KB) : " << std::fixed << std::setprecision(2) << mb_s_1k << " MB/s\n";
    std::cout << "  --> Throughput (64 KB): " << std::fixed << std::setprecision(2) << mb_s_64k << " MB/s\n";

    // 4. End-to-End Session Handshake Latency
    bench::print_header("4. Full Session Handshake Latency");
    bench::print_row("E2E Handshake Exchange", bench::measure([&]() {
        aegis::session::aegis_session alice(aegis::security_level::nist_level_3);
        aegis::session::aegis_session bob(aegis::security_level::nist_level_3);

        alice.initialize_identity();
        bob.initialize_identity();

        auto pub_bundle = alice.export_public_key_bundle();
        auto sig_pub = alice.export_sig_public_key();
        auto sig_bytes = alice.sign_payload(pub_bundle);

        auto enc_sec = bob.process_peer_bundle(pub_bundle, sig_bytes, sig_pub);
        alice.finalize_handshake(enc_sec.ciphertext);
        return true;
    }, 200));

    return 0;
}