/// Fuzz test: validate ClientHello parser against malformed input
#include "../src/engine.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <random>

static void test_malformed_client_hello() {
    int tests = 0, passed = 0;

    // Empty input
    {
        tests++;
        std::string sni = extract_sni(nullptr, 0);
        if (sni.empty()) passed++;
    }

    // Too short
    {
        tests++;
        uint8_t buf[] = {0x16, 0x03, 0x01}; // just 3 bytes, no full header
        std::string sni = extract_sni(buf, sizeof(buf));
        if (sni.empty()) passed++;
    }

    // Wrong record type (not HANDSHAKE)
    {
        tests++;
        uint8_t buf[64] = {0x17, 0x03, 0x01}; // APPLICATION_DATA, not HANDSHAKE
        std::string sni = extract_sni(buf, 64);
        if (sni.empty()) passed++;
    }

    // Wrong handshake type (not CLIENT_HELLO)
    {
        tests++;
        uint8_t buf[64] = {0x16, 0x03, 0x01, 0x00, 0x00, 0x02}; // HANDSHAKE, type=02 (SERVER_HELLO)
        std::string sni = extract_sni(buf, 64);
        if (sni.empty()) passed++;
    }

    // Missing session_id length
    {
        tests++;
        uint8_t buf[50] = {0x16, 0x03, 0x01, 0x00, 0x00, 0x01}; // just CLIENT_HELLO type, no random
        std::string sni = extract_sni(buf, 50);
        if (sni.empty()) passed++;
    }

    // session_id length mismatch (claims 32 but frame too short)
    {
        tests++;
        uint8_t buf[50] = {};
        buf[0]=0x16; buf[1]=0x03; buf[2]=0x01;
        buf[3]=0x00; buf[4]=0x20; // record len = 32
        buf[5]=0x01; // CLIENT_HELLO
        // No random, no sid_len - frame too short
        std::string sni = extract_sni(buf, 30);
        if (sni.empty()) passed++;
    }

    // Huge session_id length (overflow test)
    {
        tests++;
        uint8_t buf[256] = {};
        buf[0]=0x16; buf[1]=0x03; buf[2]=0x01;
        buf[3]=0x00; buf[4]=0xF0; // record len = 240
        buf[5]=0x01; // CLIENT_HELLO
        buf[6]=0x00; buf[7]=0xE0; // hs len = 224
        buf[8]=0x03; buf[9]=0x01; // version
        // random filled with 0 (32 bytes at offset 10)
        buf[42]=0xFF; // sid_len = 255 (huge, beyond buffer)
        std::string sni = extract_sni(buf, sizeof(buf));
        if (sni.empty()) passed++;
    }

    // Valid ClientHello with no extensions
    {
        tests++;
        auto frame = build_client_hello("test.com");
        std::string sni = extract_sni(frame.data(), frame.size());
        if (sni == "test.com") passed++;
    }

    // Random byte fuzzing
    {
        std::mt19937 rng(42);
        for (int i = 0; i < 100; i++) {
            tests++;
            size_t len = std::uniform_int_distribution<size_t>(1, 512)(rng);
            std::vector<uint8_t> buf(len);
            for (auto& b : buf) b = (uint8_t)rng();
            // Should not crash
            std::string sni = extract_sni(buf.data(), buf.size());
            (void)sni; // just checking no crash
            passed++;
        }
    }

    std::cout << "Fuzz: " << passed << "/" << tests << " passed\n";
}

static void test_v3_validation_fuzz() {
    int tests = 0, passed = 0;
    std::mt19937 rng(123);

    for (int i = 0; i < 100; i++) {
        tests++;
        size_t len = std::uniform_int_distribution<size_t>(1, 512)(rng);
        std::vector<uint8_t> buf(len);
        for (auto& b : buf) b = (uint8_t)rng();
        std::string sni;
        bool ok = validate_client_hello_v3(buf.data(), buf.size(), "password", sni);
        (void)ok; (void)sni;
        passed++;
    }

    std::cout << "V3 Fuzz: " << passed << "/" << tests << " passed (no crashes)\n";
}

int main() {
    test_malformed_client_hello();
    test_v3_validation_fuzz();
    std::cout << "All fuzz tests completed.\n";
    return 0;
}
