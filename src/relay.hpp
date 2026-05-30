#pragma once
// shadowtls-cpp: HMAC-relay layer for application data records
// Wire-compatible with shadow-tls v2 protocol

#include "protocol.hpp"
#include <vector>
#include <cstring>

// Default application data record header (length=0, HMAC slots empty)
inline constexpr uint8_t DEFAULT_APPDATA_HEADER[TLS_HMAC_HEADER_SIZE] = {
    APPLICATION_DATA, TLS_MAJOR, TLS_MINOR_MIN, 0, 0, 0, 0, 0, 0
};

// Build an application data record with HMAC tag
// data: plaintext to wrap
// hmac: HMAC context (mutated — call finalize() then update() with result)
// out: output buffer (resized to fit)
inline void build_appdata_record(const uint8_t* data, size_t len,
                                  HmacCtx& hmac, std::vector<uint8_t>& out) {
    size_t frame_len = len + HMAC_SIZE; // HMAC bytes after header
    out.resize(TLS_HMAC_HEADER_SIZE + len);

    // Header
    memcpy(out.data(), DEFAULT_APPDATA_HEADER, TLS_HEADER_SIZE);
    // Set record length
    write_u16(out.data() + 3, (uint16_t)frame_len);

    // Copy data
    memcpy(out.data() + TLS_HMAC_HEADER_SIZE, data, len);

    // Compute HMAC over data portion
    hmac.update(out.data() + TLS_HMAC_HEADER_SIZE, len);
    uint8_t hmac_val[HMAC_SIZE];
    hmac.finalize(hmac_val, HMAC_SIZE);
    // Feed HMAC back for chaining (shadow-tls v2 protocol)
    hmac.update(hmac_val, HMAC_SIZE);

    // Place HMAC after TLS header
    memcpy(out.data() + TLS_HEADER_SIZE, hmac_val, HMAC_SIZE);
}

// Verify and strip HMAC from an application data record
// Returns true if HMAC is valid, false otherwise
// On success, payload is placed in 'out' (without HMAC header)
inline bool verify_appdata_record(const uint8_t* frame, size_t frame_len,
                                   HmacCtx& hmac, bool update_after,
                                   std::vector<uint8_t>& payload) {
    if (frame_len < TLS_HMAC_HEADER_SIZE) return false;
    if (frame[0] != APPLICATION_DATA) return false;
    if (frame[1] != TLS_MAJOR || frame[2] != TLS_MINOR_MIN) return false;

    // Verify HMAC
    hmac.update(frame + TLS_HMAC_HEADER_SIZE, frame_len - TLS_HMAC_HEADER_SIZE);
    uint8_t expected[HMAC_SIZE];
    hmac.finalize(expected, HMAC_SIZE);

    if (update_after) {
        hmac.update(expected, HMAC_SIZE);
    }

    // Compare with embedded HMAC
    if (memcmp(frame + TLS_HEADER_SIZE, expected, HMAC_SIZE) != 0) {
        return false;
    }

    // Extract payload
    size_t payload_len = frame_len - TLS_HMAC_HEADER_SIZE;
    payload.resize(payload_len);
    memcpy(payload.data(), frame + TLS_HMAC_HEADER_SIZE, payload_len);
    return true;
}

// Frame decoder: accumulates bytes and extracts complete TLS records
class FrameDecoder {
    std::vector<uint8_t> buf_;
    size_t pos_ = 0;
public:
    void feed(const uint8_t* data, size_t len) {
        size_t old = buf_.size();
        buf_.resize(old + len);
        memcpy(buf_.data() + old, data, len);
    }

    // Returns pointer to next complete frame, or nullptr if incomplete
    // Sets out_len to frame length
    const uint8_t* next_frame(size_t& out_len) {
        if (buf_.size() - pos_ < TLS_HEADER_SIZE) return nullptr;
        const uint8_t* p = buf_.data() + pos_;
        uint16_t rec_len = read_u16(p + 3);
        size_t total = (size_t)TLS_HEADER_SIZE + rec_len;
        if (buf_.size() - pos_ < total) return nullptr;
        out_len = total;
        return p;
    }

    void consume(size_t n) {
        pos_ += n;
        if (pos_ == buf_.size()) {
            buf_.clear();
            pos_ = 0;
        }
    }

    void compact() {
        if (pos_ > 0) {
            size_t rem = buf_.size() - pos_;
            memmove(buf_.data(), buf_.data() + pos_, rem);
            buf_.resize(rem);
            pos_ = 0;
        }
    }

    bool empty() const { return pos_ >= buf_.size(); }
};
