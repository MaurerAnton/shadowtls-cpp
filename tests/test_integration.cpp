/// Integration tests: full handshake flow simulation
#include "../src/engine.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>

static int test_count = 0, pass_count = 0;
#define TEST(name) do { test_count++; try {
#define ENDTEST pass_count++; std::cout << "PASS: " << #name << "\n"; } catch(...) { std::cout << "FAIL: " << #name << "\n"; } } while(0)

// ===== Test: complete V2 handshake HMAC flow =====
static void test_v2_handshake_flow() {
    // 1. Client builds ClientHello
    auto hello = build_client_hello("test.example.com");
    assert(!hello.empty());
    assert(hello[0] == HANDSHAKE);
    assert(hello[TLS_HEADER_SIZE] == CLIENT_HELLO);

    // 2. Client initializes handshake HMAC and feeds ClientHello
    HmacCtx client_hs_hmac;
    client_hs_hmac.init((const uint8_t*)"password", 8);
    client_hs_hmac.update(hello.data(), hello.size());

    // 3. Server receives ClientHello, initializes HMAC
    HmacCtx server_hs_hmac;
    server_hs_hmac.init((const uint8_t*)"password", 8);
    server_hs_hmac.update(hello.data(), hello.size());

    // 4. Both should produce same HMAC
    uint8_t client_result[HMAC_SIZE_V2], server_result[HMAC_SIZE_V2];
    client_hs_hmac.finalize(client_result, HMAC_SIZE_V2);
    server_hs_hmac.finalize(server_result, HMAC_SIZE_V2);
    assert(memcmp(client_result, server_result, HMAC_SIZE_V2) == 0);

    // 5. Client builds first APPLICATION_DATA with handshake HMAC
    const char* payload = "HELLO";
    std::vector<uint8_t> first_frame;
    HmacCtx client_hs_copy = client_hs_hmac; // won't work after finalize, use fresh
    HmacCtx fresh_hs;
    fresh_hs.init((const uint8_t*)"password", 8);
    fresh_hs.update(hello.data(), hello.size());
    build_first_appdata((const uint8_t*)payload, 5, fresh_hs, first_frame);

    // 6. Server verifies first APPLICATION_DATA
    HmacCtx verify_hs;
    verify_hs.init((const uint8_t*)"password", 8);
    verify_hs.update(hello.data(), hello.size());
    std::vector<uint8_t> verified_payload;
    bool ok = verify_first_appdata(first_frame.data(), first_frame.size(), verify_hs, verified_payload);
    assert(ok);
    assert(verified_payload.size() == 5);
    assert(memcmp(verified_payload.data(), payload, 5) == 0);

    std::cout << "PASS: v2_handshake_flow\n";
    pass_count++;
}

// ===== Test: V2 auth failure with wrong password =====
static void test_v2_auth_failure() {
    auto hello = build_client_hello("test.com");

    HmacCtx good_hs;
    good_hs.init((const uint8_t*)"password", 8);
    good_hs.update(hello.data(), hello.size());

    std::vector<uint8_t> frame;
    build_first_appdata((const uint8_t*)"data", 4, good_hs, frame);

    // Verify with wrong password
    HmacCtx bad_hs;
    bad_hs.init((const uint8_t*)"wrongpass", 9);
    bad_hs.update(hello.data(), hello.size());
    std::vector<uint8_t> payload;
    bool ok = verify_first_appdata(frame.data(), frame.size(), bad_hs, payload);
    assert(!ok);

    std::cout << "PASS: v2_auth_failure\n";
    pass_count++;
}

// ===== Test: V3 XOR roundtrip =====
static void test_v3_xor_roundtrip() {
    std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04};
    uint8_t data[] = "HELLO WORLD TEST";
    size_t len = strlen((char*)data);

    // XOR
    v3_xor_data(data, len, key);
    // XOR back
    v3_xor_data(data, len, key);
    assert(memcmp(data, "HELLO WORLD TEST", len) == 0);

    std::cout << "PASS: v3_xor_roundtrip\n";
    pass_count++;
}

// ===== Test: V3 build + verify appdata =====
static void test_v3_appdata_flow() {
    std::vector<uint8_t> xor_key(32, 0xAA);
    const uint8_t* plain = (const uint8_t*)"TESTDATA";

    HmacCtx hmac_send;
    hmac_send.init((const uint8_t*)"key", 3);
    hmac_send.update((const uint8_t*)"S", 1);

    HmacCtx hmac_recv;
    hmac_recv.init((const uint8_t*)"key", 3);
    hmac_recv.update((const uint8_t*)"S", 1);

    std::vector<uint8_t> frame;
    v3_build_appdata(plain, 8, xor_key, hmac_send, frame);
    assert(frame[0] == APPLICATION_DATA);

    std::vector<uint8_t> recovered;
    bool ok = v3_verify_appdata(frame.data(), frame.size(), xor_key, hmac_recv, recovered);
    assert(ok);
    assert(recovered.size() == 8);
    assert(memcmp(recovered.data(), plain, 8) == 0);

    std::cout << "PASS: v3_appdata_flow\n";
    pass_count++;
}

// ===== Test: FrameDecoder =====
static void test_frame_decoder() {
    FrameDecoder fd;
    uint8_t data[] = {
        0x17, 0x03, 0x01, 0x00, 0x03, // APP_DATA, len=3
        0xAA, 0xBB, 0xCC,
        0x16, 0x03, 0x01, 0x00, 0x02, // HANDSHAKE, len=2
        0xDD, 0xEE
    };
    fd.feed(data, sizeof(data));

    size_t flen; const uint8_t* f;
    f = fd.next_frame(flen);
    assert(f != nullptr && flen == 8); // 5 header + 3 data
    assert(f[0] == APPLICATION_DATA);
    fd.consume(flen);

    f = fd.next_frame(flen);
    assert(f != nullptr && flen == 7); // 5 header + 2 data
    assert(f[0] == HANDSHAKE);
    fd.consume(flen);

    f = fd.next_frame(flen);
    assert(f == nullptr); // no more frames

    std::cout << "PASS: frame_decoder\n";
    pass_count++;
}

// ===== Test: HMAC chaining consistency =====
static void test_hmac_chaining() {
    HmacCtx h1, h2;
    h1.init((const uint8_t*)"key", 3);
    h2.init((const uint8_t*)"key", 3);

    const uint8_t* d1 = (const uint8_t*)"packet1";
    const uint8_t* d2 = (const uint8_t*)"packet2";

    // Chain manually
    h1.update(d1, 7);
    uint8_t tag1[HMAC_SIZE]; h1.finalize(tag1, HMAC_SIZE);
    h1.update(tag1, HMAC_SIZE); // chain
    h1.update(d2, 7);
    uint8_t tag2[HMAC_SIZE]; h1.finalize(tag2, HMAC_SIZE);

    // Verify with same chain
    h2.update(d1, 7);
    uint8_t exp1[HMAC_SIZE]; h2.finalize(exp1, HMAC_SIZE);
    assert(memcmp(tag1, exp1, HMAC_SIZE) == 0);
    h2.update(exp1, HMAC_SIZE);
    h2.update(d2, 7);
    uint8_t exp2[HMAC_SIZE]; h2.finalize(exp2, HMAC_SIZE);
    assert(memcmp(tag2, exp2, HMAC_SIZE) == 0);

    std::cout << "PASS: hmac_chaining\n";
    pass_count++;
}

// ===== Test: build_server_hello =====
static void test_build_server_hello() {
    uint8_t cr[32] = {};
    uint8_t sid[32] = {};
    auto sh = build_server_hello(cr, sid, 32);
    assert(!sh.empty());
    assert(sh[0] == HANDSHAKE);
    assert(sh[TLS_HEADER_SIZE] == SERVER_HELLO);

    uint8_t sr[TLS_RANDOM_SIZE];
    assert(extract_server_random(sh.data(), sh.size(), sr));
    std::cout << "PASS: build_server_hello\n";
    pass_count++;
}

int main() {
    test_count = 0; pass_count = 0;
    test_v2_handshake_flow(); test_count++;
    test_v2_auth_failure(); test_count++;
    test_v3_xor_roundtrip(); test_count++;
    test_v3_appdata_flow(); test_count++;
    test_frame_decoder(); test_count++;
    test_hmac_chaining(); test_count++;
    test_build_server_hello(); test_count++;
    std::cout << "\n" << pass_count << "/" << test_count << " tests passed.\n";
    return pass_count == test_count ? 0 : 1;
}
