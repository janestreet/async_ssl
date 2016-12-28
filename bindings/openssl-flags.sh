#!/bin/bash

set -e

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

cclibs=""
for i in $openssl_cclib; do
    case $i in
        -l*)
            cclibs="$cclibs ${i/-l}"
            ;;
        *)
            ;;
    esac
done

echo "(${cclibs})" > openssl-cclib.sexp
echo "(${openssl_ccopt})" > openssl-ccopt.sexp
echo "${openssl_cclib}" > openssl-cclib
echo "${openssl_ccopt}" > openssl-ccopt

