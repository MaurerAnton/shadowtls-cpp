/// Benchmark: throughput measurement for HMAC appdata relay
#include "../src/engine.hpp"
#include <iostream>
#include <chrono>

static void bench_hmac_throughput() {
    const size_t N = 100000;
    const size_t PAYLOAD = 1400; // typical MTU-sized payload

    // Setup HMAC contexts
    uint8_t sr[TLS_RANDOM_SIZE] = {};
    HmacCtx hmac_add, hmac_verify;
    auto key = kdf("benchpass", sr, 32);
    hmac_add.init(key.data(), key.size()); hmac_add.update((uint8_t*)"C", 1);
    hmac_verify.init(key.data(), key.size()); hmac_verify.update((uint8_t*)"C", 1);

    std::vector<uint8_t> plain(PAYLOAD);
    for (auto& b : plain) b = (uint8_t)(rand() & 0xFF);

    auto start = std::chrono::steady_clock::now();

    for (size_t i = 0; i < N; i++) {
        // Build appdata record
        std::vector<uint8_t> frame;
        build_appdata_record(plain.data(), PAYLOAD, hmac_add, frame);

        // Verify
        std::vector<uint8_t> recovered;
        bool ok = verify_appdata_record(frame.data(), frame.size(), hmac_verify, true, recovered);
        if (!ok || recovered.size() != PAYLOAD) {
            std::cerr << "Benchmark integrity failure at iteration " << i << "\n";
            return;
        }
    }

    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double mbps = (double)(N * PAYLOAD * 2) / (elapsed / 1000.0) / (1024 * 1024);

    std::cout << "HMAC relay: " << N << " packets of " << PAYLOAD << "B in "
              << elapsed << "ms = " << mbps << " MB/s\n";
}

static void bench_tls_parsing() {
    const size_t N = 50000;
    auto hello = build_client_hello("bench.example.org");

    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < N; i++) {
        std::string sni = extract_sni(hello.data(), hello.size());
        if (sni != "bench.example.org") { std::cerr << "SNI mismatch\n"; return; }
    }
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "SNI parsing: " << N << " iterations in " << elapsed << "ms ("
              << (elapsed * 1000.0 / N) << " us/op)\n";
}

int main() {
    bench_hmac_throughput();
    bench_tls_parsing();
    std::cout << "Benchmarks complete.\n";
    return 0;
}
