#!/bin/bash

set -eu -o pipefail 


cd "$(dirname "$0")" 

echo "[!Manual tester!] \
In a failing case this should trigger a segfault within seconds."

./async_ssl_stress_test_server.exe &>/tmp/async_ssl_stress_test_sertver_output.txt & 

TEST_PID=$!

function run_test (){
  i=1
  while true ; do
    if [ $(( i  % 256 )) = 0 ]; then
	echo "Checking now"
        if ! ps -p "$TEST_PID" > /dev/null ; then echo "Not running"; exit -1 ; fi
    fi
    curl -k  https://127.0.0.1:4567 --ciphers 'dhe_rsa_aes_256_gcm_sha_384'  &> /dev/null &
    printf "."
    i=$((i+1))
  done
}

function finish {
  exec 3>&2 # Copy stderr
  exec 2>/dev/null # suppress stderr, so we don't see all the killed messages
  # Ensure all the jobs get killed
  kill -9 "$TEST_PID" &> /dev/null || true
  killall -9 curl &> /dev/null || true
  # Wait for everything to finish
  wait &> /dev/null || true
  exec 2>&3 # restore stderr
  echo  >&2
  echo  >&2
  echo === Test server output === >&2
  cat /tmp/async_ssl_stress_test_sertver_output.txt >&2
}
trap finish EXIT

run_test

