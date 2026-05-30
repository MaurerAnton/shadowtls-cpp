#include "protocol.hpp"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cstdio>

// ============ HmacCtx ============
HmacCtx::HmacCtx() : ctx_(nullptr), initialized_(false) {}
HmacCtx::~HmacCtx() { if (ctx_) HMAC_CTX_free((HMAC_CTX*)ctx_); }

HmacCtx::HmacCtx(const HmacCtx& o) : ctx_(nullptr), initialized_(o.initialized_) {
    if (initialized_) {
        ctx_ = HMAC_CTX_new();
        HMAC_CTX_copy((HMAC_CTX*)ctx_, (HMAC_CTX*)o.ctx_);
    }
}

HmacCtx& HmacCtx::operator=(const HmacCtx& o) {
    if (this != &o) {
        if (ctx_) HMAC_CTX_free((HMAC_CTX*)ctx_);
        initialized_ = o.initialized_;
        if (initialized_) {
            ctx_ = HMAC_CTX_new();
            HMAC_CTX_copy((HMAC_CTX*)ctx_, (HMAC_CTX*)o.ctx_);
        } else {
            ctx_ = nullptr;
        }
    }
    return *this;
}

void HmacCtx::init(const uint8_t* key, size_t key_len) {
    if (ctx_) HMAC_CTX_free((HMAC_CTX*)ctx_);
    ctx_ = HMAC_CTX_new();
    HMAC_Init_ex((HMAC_CTX*)ctx_, key, (int)key_len, EVP_sha1(), nullptr);
    initialized_ = true;
}

void HmacCtx::update(const uint8_t* data, size_t len) {
    HMAC_Update((HMAC_CTX*)ctx_, data, len);
}

void HmacCtx::finalize(uint8_t* out, size_t out_len) {
    unsigned int len;
    uint8_t hash[EVP_MAX_MD_SIZE];
    HMAC_Final((HMAC_CTX*)ctx_, hash, &len);
    memcpy(out, hash, std::min(out_len, (size_t)len));
}

HmacCtx HmacCtx::clone() const { return *this; }

// ============ Utility ============
void xor_slice(uint8_t* data, size_t len, const uint8_t* key, size_t key_len) {
    for (size_t i = 0; i < len; i++) data[i] ^= key[i % key_len];
}

std::vector<uint8_t> kdf(const std::string& password, const uint8_t* server_random, size_t len) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password.data(), password.size());
    SHA256_Update(&ctx, server_random, len);
    SHA256_Final(hash.data(), &ctx);
    return hash;
}

std::vector<uint8_t> sha256(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data, len, hash.data());
    return hash;
}

void random_bytes(uint8_t* buf, size_t len) {
    RAND_bytes(buf, (int)len);
}

// Parse ServerHello extensions to detect TLS 1.3 support
bool support_tls13(const uint8_t* buf, size_t len) {
    if (len < SESSION_ID_LEN_IDX) return false;
    size_t pos = SESSION_ID_LEN_IDX;
    // Skip session ID
    if (pos >= len) return false;
    uint8_t sid_len = buf[pos++];
    if (pos + sid_len > len) return false;
    pos += sid_len;
    // Skip cipher suite (2 len + 2 suite = 4 bytes) + compression (1 count + 1 method = 2 bytes)
    if (pos + 10 > len) return false;
    pos += 10; // ciphers(8) + comp(2)
    // Extensions length (2 bytes)
    if (pos + 2 > len) return false;
    uint16_t ext_len = read_u16(buf + pos);
    pos += 2;
    size_t ext_end = pos + ext_len;
    if (ext_end > len) return false;

    for (; pos + 4 <= ext_end;) {
        uint16_t etype = read_u16(buf + pos);
        uint16_t elen  = read_u16(buf + pos + 2);
        pos += 4;
        if (pos + elen > ext_end) return false;
        if (etype == SUPPORTED_VERSIONS && elen == 2) {
            uint16_t ver = read_u16(buf + pos);
            return ver == TLS_13;
        }
        pos += elen;
    }
    return false;
}

// Build a 31-byte encrypted alert record (TLS 1.2)
void build_alert(uint8_t* out) {
    memset(out, 0, 31);
    out[0] = ALERT;
    out[1] = TLS_MAJOR;
    out[2] = TLS_MINOR_MIN;
    out[3] = 0;
    out[4] = 31 - TLS_HEADER_SIZE;
    random_bytes(out + TLS_HEADER_SIZE, 31 - TLS_HEADER_SIZE);
}

// Parse "host:port" or "[host]:port"
bool parse_addr(const std::string& s, std::string& host, int& port) {
    size_t col = s.rfind(':');
    if (col == std::string::npos) return false;
    port = std::stoi(s.substr(col + 1));
    if (s[0] == '[') {
        size_t rb = s.find(']');
        if (rb == std::string::npos || rb >= col) return false;
        host = s.substr(1, rb - 1);
    } else {
        host = s.substr(0, col);
    }
    return true;
}
