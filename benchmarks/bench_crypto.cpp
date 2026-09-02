#include "aegis/policy_manager.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <numeric>
#include <algorithm>
#include <iomanip>

struct bench_stats {
    double mean_us;
    double min_us;
    double max_us;
    double ops_per_sec;
};

template <typename Func>
bench_stats run_benchmark(std::string_view name, size_t iterations, Func&& func) {
    std::vector<double> timings;
    timings.reserve(iterations);

    // Warm-up run
    func();

    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        func();
        auto end = std::chrono::high_resolution_clock::now();
        
        double duration_us = std::chrono::duration<double, std::micro>(end - start).count();
        timings.push_back(duration_us);
    }

    double sum = std::accumulate(timings.begin(), timings.end(), 0.0);
    double mean = sum / static_cast<double>(iterations);
    double min_val = *std::min_element(timings.begin(), timings.end());
    double max_val = *std::max_element(timings.begin(), timings.end());
    double ops_sec = 1'000'000.0 / mean;

    std::cout << std::left << std::setw(32) << name
              << " | Mean: " << std::right << std::setw(8) << std::fixed << std::setprecision(2) << mean << " us"
              << " | Min: "  << std::setw(8) << min_val << " us"
              << " | Max: "  << std::setw(8) << max_val << " us"
              << " | "      << std::setw(8) << static_cast<uint64_t>(ops_sec) << " ops/s\n";

    return {mean, min_val, max_val, ops_sec};
}

int main() {
    constexpr size_t iterations = 500;
    std::cout << " AEGIS PQC PERFORMANCE BENCHMARK (" << iterations << " iterations per operation)\n\n";

    aegis::policy::crypto_agility_engine agility(aegis::security_level::nist_level_3);
    auto kem = agility.create_kem_engine();
    auto sig = agility.create_signature_engine();

    // 1. Benchmark Hybrid KEM (X25519 + ML-KEM-768)
    aegis::key_pair kem_keys;
    aegis::encapsulated_secret secret;

    run_benchmark("Hybrid KEM KeyGen", iterations, [&]() {
        kem_keys = kem->generate_keypair();
    });

    run_benchmark("Hybrid KEM Encapsulate", iterations, [&]() {
        secret = kem->encapsulate(kem_keys.public_key);
    });

    run_benchmark("Hybrid KEM Decapsulate", iterations, [&]() {
        auto key = kem->decapsulate(secret.ciphertext, kem_keys.secret_key);
    });

    std::cout << "----------------------------------------------------------------------------------------\n";

    // 2. Benchmark Signature Scheme (ML-DSA-65)
    aegis::key_pair sig_keys;
    std::vector<uint8_t> message(1024, 0xAB); // 1 KB sample payload
    std::vector<uint8_t> signature;

    run_benchmark("ML-DSA-65 KeyGen", iterations, [&]() {
        sig_keys = sig->generate_keypair();
    });

    run_benchmark("ML-DSA-65 Sign (1 KB)", iterations, [&]() {
        signature = sig->sign(message, sig_keys.secret_key);
    });

    run_benchmark("ML-DSA-65 Verify (1 KB)", iterations, [&]() {
        bool ok = sig->verify(message, signature, sig_keys.public_key);
    });

    return 0;
}