#pragma once
// shadowtls-cpp types: RAII handles, constants, logging, Conn, config
#include "protocol.hpp"
#include "relay.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <thread>
#include <mutex>
#include <atomic>
#include <map>
#include <array>
#include <algorithm>
#include <memory>
#include <random>

// ===== Constants =====
inline constexpr size_t EPOLL_MAX_EVENTS = 256;
inline constexpr size_t IO_BUF_SIZE       = 8192;
inline constexpr size_t LISTEN_BACKLOG    = 128;
inline constexpr int    KEEPALIVE_IDLE    = 90;
inline constexpr int    KEEPALIVE_INTVL   = 90;
inline constexpr int    KEEPALIVE_CNT     = 2;
inline constexpr int    FASTOPEN_QLEN     = 128;

// ===== Logging =====
enum class LogLevel { ERROR = 0, WARN = 1, INFO = 2, DEBUG = 3 };
inline LogLevel g_log_level = LogLevel::INFO;

#define LOG(level, fmt, ...) do { \
    if ((int)(level) <= (int)g_log_level) \
        fprintf(stderr, "[%s] " fmt "\n", \
            (level) == LogLevel::ERROR ? "ERR" : \
            (level) == LogLevel::WARN  ? "WRN" : \
            (level) == LogLevel::INFO  ? "INF" : "DBG", ##__VA_ARGS__); \
} while(0)

// ===== RAII SSL handles =====
struct SslCtx {
    SSL_CTX* ptr = nullptr;
    SslCtx() = default;
    explicit SslCtx(SSL_CTX* p) : ptr(p) {}
    ~SslCtx() { if (ptr) SSL_CTX_free(ptr); }
    SslCtx(SslCtx&& o) noexcept : ptr(o.ptr) { o.ptr = nullptr; }
    SslCtx& operator=(SslCtx&& o) noexcept { if (ptr) SSL_CTX_free(ptr); ptr = o.ptr; o.ptr = nullptr; return *this; }
    operator SSL_CTX*() const { return ptr; }
    SslCtx(const SslCtx&) = delete;
    SslCtx& operator=(const SslCtx&) = delete;
};

struct SslHandle {
    SSL* ptr = nullptr;
    SslHandle() = default;
    explicit SslHandle(SSL* p) : ptr(p) {}
    ~SslHandle() { if (ptr) SSL_free(ptr); }
    SslHandle(SslHandle&& o) noexcept : ptr(o.ptr) { o.ptr = nullptr; }
    SslHandle& operator=(SslHandle&& o) noexcept { if (ptr) SSL_free(ptr); ptr = o.ptr; o.ptr = nullptr; return *this; }
    operator SSL*() const { return ptr; }
    SslHandle(const SslHandle&) = delete;
    SslHandle& operator=(const SslHandle&) = delete;
};

struct BioHandle {
    BIO* ptr = nullptr;
    BioHandle() = default;
    explicit BioHandle(BIO* p) : ptr(p) {}
    ~BioHandle() { if (ptr) BIO_free(ptr); }
    BioHandle(BioHandle&& o) noexcept : ptr(o.ptr) { o.ptr = nullptr; }
    BioHandle& operator=(BioHandle&& o) noexcept { if (ptr) BIO_free(ptr); ptr = o.ptr; o.ptr = nullptr; return *this; }
    operator BIO*() const { return ptr; }
    BioHandle(const BioHandle&) = delete;
    BioHandle& operator=(const BioHandle&) = delete;
};

// ===== Configuration =====
struct TlsAddrs {
    std::map<std::string, std::string> dispatch;
    std::string fallback;
    WildcardSNI wildcard = WildcardSNI::Off;
    static TlsAddrs parse(const std::string& arg);
    std::string find(const std::string& sni, bool authed) const;
private:
    static std::vector<std::string> split(const std::string& s, char delim);
};

struct Config {
    std::string listen_addr  = "[::1]:8080";
    std::string target_addr;
    std::string tls_host;
    TlsAddrs    tls_addrs;
    std::string password;
    bool        server_mode = false;
    bool        nodelay      = true;
    bool        fastopen     = false;
    V3Mode      v3           = V3Mode::Disabled;
    int         threads      = 0;
    WildcardSNI wildcard     = WildcardSNI::Off;
    std::vector<std::string> alpn;
};

// ===== Handshake phase =====
enum class HsPhase {
    ClientSendHello, ClientTlsHandshake, ClientWaitHello,
    ServerReadHello, ServerForwardHello, ServerWaitTlsHello,
    ServerBidirRelay, ServerConnectData, Done
};

// ===== Connection state =====
struct Conn {
    int fd = -1, peer_fd = -1;
    std::vector<uint8_t> inbuf, outbuf;
    FrameDecoder frame_decoder;
    HsPhase hs_phase = HsPhase::Done;
    bool handshake_done = false;
    HmacCtx hmac_add, hmac_verify, hmac_ignore;
    bool hmac_ignore_active = false;
    HmacCtx handshake_hmac;
    bool handshake_hmac_init = false;
    bool first_appdata_sent = false, first_appdata_checked = false;
    bool is_tls_side = false, accepted_from_listener = false;
    std::string password;
    uint8_t server_random[TLS_RANDOM_SIZE] = {};
    std::vector<uint8_t> v3_xor_key;
    bool v3_mode = false;
    SslCtx ssl_ctx; SslHandle ssl; BioHandle bio_net, bio_in;
    bool tls_handshake_done = false;
    bool seen_handshake = false, seen_ccs = false, direct_proxy = false;
    int  appdata_attempts = 0, hmac_ring_pos = 0, hmac_ring_count = 0;
    uint8_t hmac_ring[10][HMAC_SIZE_V2];
    Conn() = default;
    ~Conn() = default; // fds closed by close_conn, memory by g_conns unique_ptr
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;
};

using ConnPtr = std::unique_ptr<Conn>;

// ===== Global state =====
extern std::atomic<bool> g_running;
extern std::map<int, ConnPtr> g_conns;
extern std::mutex g_conns_mutex;

// ===== RNG =====
inline std::mt19937& rng() { static std::mt19937 r(std::random_device{}()); return r; }
