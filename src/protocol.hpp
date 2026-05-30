#pragma once
// shadowtls-cpp: Wire-compatible C++ port of shadow-tls
// Protocol constants and common utilities

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

// TLS record layer constants
inline constexpr uint8_t  TLS_MAJOR           = 0x03;
inline constexpr uint8_t  TLS_MINOR_MAJ       = 0x03;  // TLS 1.2 minor
inline constexpr uint8_t  TLS_MINOR_MIN       = 0x01;
inline constexpr uint16_t SNI_EXT_TYPE        = 0;
inline constexpr uint16_t SUPPORTED_VERSIONS  = 43;
inline constexpr size_t   TLS_RANDOM_SIZE     = 32;
inline constexpr size_t   TLS_HEADER_SIZE     = 5;
inline constexpr size_t   TLS_SESSION_ID_SIZE = 32;

// TLS record types
inline constexpr uint8_t CLIENT_HELLO       = 0x01;
inline constexpr uint8_t SERVER_HELLO       = 0x02;
inline constexpr uint8_t ALERT              = 0x15;
inline constexpr uint8_t HANDSHAKE          = 0x16;
inline constexpr uint8_t APPLICATION_DATA   = 0x17;
inline constexpr uint8_t CHANGE_CIPHER_SPEC = 0x14;

// Offsets in ClientHello/ServerHello
inline constexpr size_t SERVER_RANDOM_IDX   = TLS_HEADER_SIZE + 1 + 3 + 2;
inline constexpr size_t SESSION_ID_LEN_IDX  = SERVER_RANDOM_IDX + TLS_RANDOM_SIZE;

// HMAC size
inline constexpr size_t HMAC_SIZE    = 4;
inline constexpr size_t HMAC_SIZE_V2 = 8;
inline constexpr size_t TLS_HMAC_HEADER_SIZE = TLS_HEADER_SIZE + HMAC_SIZE;

// Buffer
inline constexpr size_t COPY_BUF_SIZE = 4096;
inline constexpr size_t TLS_13        = 0x0304;

// V3 protocol mode
enum class V3Mode { Disabled, Lossy, Strict };

// Wildcard SNI mode
enum class WildcardSNI { Off, Authed, All };

// HMAC wrapper using OpenSSL
class HmacCtx {
    void* ctx_; // HMAC_CTX*
    bool initialized_;
public:
    HmacCtx();
    ~HmacCtx();
    HmacCtx(const HmacCtx&);
    HmacCtx& operator=(const HmacCtx&);

    void init(const uint8_t* key, size_t key_len);
    void update(const uint8_t* data, size_t len);
    void finalize(uint8_t* out, size_t out_len); // takes first out_len bytes
    HmacCtx clone() const;
};

// Utility functions
void xor_slice(uint8_t* data, size_t len, const uint8_t* key, size_t key_len);
std::vector<uint8_t> kdf(const std::string& password, const uint8_t* server_random, size_t len);
std::vector<uint8_t> sha256(const uint8_t* data, size_t len);
void random_bytes(uint8_t* buf, size_t len);

// TLS record helpers
bool support_tls13(const uint8_t* buf, size_t len);
void build_alert(uint8_t* out); // 31-byte TLS Alert record

// Read/write big-endian helpers
inline uint16_t read_u16(const uint8_t* p) { return (uint16_t(p[0]) << 8) | p[1]; }
inline void write_u16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
inline uint8_t read_u8(const uint8_t* p) { return p[0]; }
inline void write_u24(uint8_t* p, uint32_t v) { p[0]=uint8_t(v>>16); p[1]=uint8_t(v>>8); p[2]=uint8_t(v); }

// Address parsing
bool parse_addr(const std::string& s, std::string& host, int& port);
