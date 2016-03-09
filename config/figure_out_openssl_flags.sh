#!/bin/sh

set -e

if [ -e setup.data ]; then
    sed '/^openssl_cc\(lib\|opt\)=/d' setup.data > setup.data.new
    mv setup.data.new setup.data
fi

openssl_cclib="-lssl -lcrypto"
openssl_ccopt=""

if which pkg-config > /dev/null 2> /dev/null; then
    # Hack for OSX
    BREW_PREFIX="`brew --prefix 2> /dev/null || echo /`"
    export PKG_CONFIG_PATH=$BREW_PREFIX/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH
    if pkg-config openssl 2> /dev/null; then
        openssl_cclib="`pkg-config --libs openssl`"
        openssl_ccopt="`pkg-config --cflags openssl`"
    fi
fi

cat >> setup.data <<EOF
openssl_cclib="$openssl_cclib"
openssl_ccopt="$openssl_ccopt"
EOF

