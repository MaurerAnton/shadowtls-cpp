#!/bin/bash
# Build static OpenSSL for cross-compilation with musl
# Usage: ./scripts/build-openssl.sh <target-triplet> <install-prefix>
# Example: ./scripts/build-openssl.sh x86_64-linux-musl /tmp/openssl-x86_64
set -e

TARGET="$1"
PREFIX="${2:-/tmp/openssl-${TARGET}}"
OPENSSL_VERSION="3.4.0"

case "$TARGET" in
    x86_64-linux-musl)
        OPENSSL_TARGET="linux-x86_64"
        CC="x86_64-linux-musl-gcc"
        CXX="x86_64-linux-musl-g++"
        ;;
    aarch64-linux-musl)
        OPENSSL_TARGET="linux-aarch64"
        CC="aarch64-linux-musl-gcc"
        CXX="aarch64-linux-musl-g++"
        ;;
    arm-linux-musleabi)
        OPENSSL_TARGET="linux-armv4"
        CC="arm-linux-musleabi-gcc"
        CXX="arm-linux-musleabi-g++"
        ;;
    armv7-linux-musleabihf)
        OPENSSL_TARGET="linux-armv4"
        CC="arm-linux-musleabihf-gcc"
        CXX="arm-linux-musleabihf-g++"
        ;;
    *)
        echo "Unknown target: $TARGET"
        exit 1
        ;;
esac

# Download and build OpenSSL
curl -fsSL "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" | tar xz
cd "openssl-${OPENSSL_VERSION}"

./Configure "$OPENSSL_TARGET" no-shared no-tests --prefix="$PREFIX" --openssldir="$PREFIX/ssl"
make -j$(nproc)
make install_sw

echo "OpenSSL built for $TARGET at $PREFIX"
