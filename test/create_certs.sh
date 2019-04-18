#!/bin/bash

echo "Generate snakeoil CA and cert"

# CA
openssl genrsa -out snakeoil_ca.key 2048
openssl req -x509 -new -nodes -key snakeoil_ca.key -sha256 -days 9000 -out snakeoil_ca.pem

# key + csr
openssl genrsa -out snakeoil.key 2048
openssl req -new -key snakeoil.key -out snakeoil.csr

# sign csr, create crt
openssl x509 -req -in snakeoil.csr -CA snakeoil_ca.pem -CAkey snakeoil_ca.key -out snakeoil.crt -days 9000 -sha256 -set_serial 1

