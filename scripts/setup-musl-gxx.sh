#!/bin/bash
# Create musl-g++ wrapper for static musl builds
set -e

# Find musl specs file
SPECS=$(musl-gcc -v 2>&1 | grep specs | awk '{print $NF}' | head -1)
[ -z "$SPECS" ] && SPECS=/usr/lib/x86_64-linux-musl/musl-gcc.specs

cat > /tmp/musl-g++ << 'ENDOFWRAPPER'
#!/bin/sh
exec /usr/bin/g++ -specs SPECSPLACEHOLDER "$@"
ENDOFWRAPPER

sed -i "s|SPECSPLACEHOLDER|$SPECS|" /tmp/musl-g++
chmod +x /tmp/musl-g++
sudo mv /tmp/musl-g++ /usr/local/bin/musl-g++
echo "Created musl-g++ with specs: $SPECS"
