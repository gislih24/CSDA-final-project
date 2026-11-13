#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ -e certs ]]; then
  openssl verify -CAfile certs/ca.pem -verify_hostname bench.test certs/server.pem
  [[ -s certs/server.key ]] || {
    echo 'Incomplete certs directory.' >&2
    exit 1
  }
  echo 'Reusing existing benchmark certificates.'
  exit 0
fi
umask 077
mkdir certs
openssl req -x509 -newkey rsa:2048 -noenc -sha256 -days 30 \
  -subj '/CN=PQC benchmark local CA' -keyout certs/ca.key -out certs/ca.pem \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -new -newkey rsa:2048 -noenc -sha256 -subj '/CN=bench.test' \
  -keyout certs/server.key -out certs/server.csr
cat >certs/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:bench.test
EOF
openssl x509 -req -in certs/server.csr -CA certs/ca.pem -CAkey certs/ca.key \
  -set_serial 2 -days 30 -sha256 -extfile certs/server.ext -out certs/server.pem
openssl verify -CAfile certs/ca.pem -verify_hostname bench.test certs/server.pem
