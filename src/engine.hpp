#pragma once
// shadowtls-cpp engine: socket helpers, protocol functions, EventLoop
#include "types.hpp"

// ===== Socket helpers =====
int  create_socket(bool v6 = true);
void set_nodelay(int fd);
void set_reuseaddr(int fd);
void set_keepalive(int fd);
void set_fastopen_connect(int fd);
bool resolve(const std::string& host, int port, sockaddr_storage& addr, socklen_t& alen);
void resolve_async(const std::string& host, int port,
                   sockaddr_storage* out_addr, socklen_t* out_alen,
                   std::atomic<bool>* done, std::atomic<bool>* ok);

// ===== TLS record parsing =====
std::string extract_sni(const uint8_t* frame, size_t len);
bool extract_server_random(const uint8_t* frame, size_t len, uint8_t* out_random);

// ===== Client Hello builders =====
std::vector<uint8_t> build_client_hello(const std::string& sni,
                                         const std::vector<std::string>& alpn_list = {});
std::vector<uint8_t> build_client_hello_v3(const std::string& sni, const std::string& password,
                                            const std::vector<std::string>& alpn_list = {});
std::vector<uint8_t> build_server_hello(const uint8_t* client_random,
                                         const uint8_t* session_id, uint8_t sid_len);

// ===== V2 first-appdata auth =====
void build_first_appdata(const uint8_t* data, size_t len, HmacCtx& hs_hmac, std::vector<uint8_t>& out);
bool verify_first_appdata(const uint8_t* frame, size_t len, HmacCtx& hs_hmac,
                           std::vector<uint8_t>& payload);

// ===== V3 protocol =====
bool validate_client_hello_v3(const uint8_t* frame, size_t len,
                               const std::string& password, std::string& out_sni);
bool detect_tls13(const uint8_t* frame, size_t len);
void build_fake_request(std::vector<uint8_t>& out);
void v3_xor_data(uint8_t* data, size_t len, const std::vector<uint8_t>& xor_key);
void v3_build_appdata(const uint8_t* plain, size_t len, const std::vector<uint8_t>& xor_key,
                       HmacCtx& hmac, std::vector<uint8_t>& out);
bool v3_verify_appdata(const uint8_t* frame, size_t flen, const std::vector<uint8_t>& xor_key,
                        HmacCtx& hmac, std::vector<uint8_t>& payload);

// ===== HMAC setup =====
void setup_hmac_from_random(Conn* c, const uint8_t* server_random, bool is_server);

// ===== Config parsing =====
bool parse_sip003(Config& cfg, std::string& mode);
bool load_config_file(const std::string& path, Config& cfg, std::string& mode);
void print_usage(const char* prog);

// ===== Event loop =====
class EventLoop {
    int epfd_ = -1, listener_ = -1;
    Config cfg_;
public:
    explicit EventLoop(const Config& c);
    ~EventLoop();
    void set_listener(int fd);
    void add_fd(int fd, uint32_t ev, Conn* c);
    void mod_fd(int fd, uint32_t ev);
    void del_fd(int fd);
    void run();
private:
    void accept_conn();
    void handle_read(Conn* c);
    void handle_write(Conn* c);
    void close_conn(Conn* c);
    void handle_read_handshake(Conn* c, const uint8_t* data, size_t len);
    void client_init_tls(Conn* remote);
    void client_tls_io(Conn* remote, bool can_read, bool can_write);
    void client_tls_done(Conn* remote);
    void client_send_hello(Conn* remote);
    void server_process_hello(Conn* client_conn, const uint8_t* data, size_t len);
    void client_got_server_hello(Conn* remote, const uint8_t* data, size_t len,
                                  uint8_t server_random[TLS_RANDOM_SIZE]);
    void connect_to_data_target(Conn* client_conn, const uint8_t* server_random);
};

int bind_listener(const std::string& addr_str, bool fastopen);
