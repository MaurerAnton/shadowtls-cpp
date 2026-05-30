#include "../src/engine.hpp"
#include <cassert>
#include <cstring>
#include <iostream>

static void test_tls_addrs() {
    // Single host → fallback:443
    auto t = TlsAddrs::parse("google.com");
    assert(t.fallback == "google.com:443");
    assert(t.dispatch.empty());
    assert(t.find("any.com", false) == "google.com:443");

    // Two hosts → first is dispatch, last is fallback
    t = TlsAddrs::parse("feishu.cn;google.com");
    assert(t.fallback == "google.com:443");
    assert(t.dispatch.size() == 1);
    assert(t.dispatch["feishu.cn"] == "feishu.cn:443");
    assert(t.find("feishu.cn", false) == "feishu.cn:443");
    assert(t.find("other.com", false) == "google.com:443");

    // Custom port: Rust-style "sni:ip:port"
    t = TlsAddrs::parse("cloudflare.com:1.2.3.4:80;google.com");
    assert(t.fallback == "google.com:443");
    assert(t.dispatch["cloudflare.com"] == "1.2.3.4:80");
    assert(t.find("cloudflare.com", false) == "1.2.3.4:80");

    // Wildcard
    t.wildcard = WildcardSNI::All;
    assert(t.find("anything.com", false) == "anything.com:443");
    t.wildcard = WildcardSNI::Authed;
    assert(t.find("authed.com", true) == "authed.com:443");
    assert(t.find("authed.com", false) == "google.com:443"); // not authed → fallback

    std::cout << "PASS: TlsAddrs\n";
}

static void test_sni_extraction() {
    auto frame = build_client_hello("cloud.tencent.com");
    std::string sni = extract_sni(frame.data(), frame.size());
    assert(sni == "cloud.tencent.com");

    auto frame2 = build_client_hello("test.example.org");
    sni = extract_sni(frame2.data(), frame2.size());
    assert(sni == "test.example.org");

    std::cout << "PASS: SNI extraction\n";
}

static void test_v3_hmac() {
    auto frame = build_client_hello_v3("test.com", "mypassword");
    std::string sni;
    bool ok = validate_client_hello_v3(frame.data(), frame.size(), "mypassword", sni);
    assert(ok);
    assert(sni == "test.com");

    // Wrong password should fail
    ok = validate_client_hello_v3(frame.data(), frame.size(), "wrongpass", sni);
    assert(!ok);

    std::cout << "PASS: V3 HMAC validation\n";
}

static void test_hmac_context() {
    HmacCtx h;
    h.init((const uint8_t*)"key", 3);
    h.update((const uint8_t*)"data", 4);
    uint8_t out1[20]; h.finalize(out1, 20);

    HmacCtx h2;
    h2.init((const uint8_t*)"key", 3);
    h2.update((const uint8_t*)"data", 4);
    uint8_t out2[20]; h2.finalize(out2, 20);

    assert(memcmp(out1, out2, 20) == 0);
    std::cout << "PASS: HMAC determinism\n";
}

int main() {
    test_tls_addrs();
    test_sni_extraction();
    test_v3_hmac();
    test_hmac_context();
    std::cout << "All tests passed.\n";
    return 0;
}
