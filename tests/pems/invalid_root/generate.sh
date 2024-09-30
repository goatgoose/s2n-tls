
set -e

rm -f *.pem

# Generate an invalid root certificate.
#
# The root is made invalid by setting the CA field in the basic constraints extension to false,
# which the libcrypto will reject as an invalid root by default.
openssl req -new -noenc -x509 \
    -newkey rsa \
    -pkeyopt rsa_keygen_bits:2048 \
    -keyout "ca-key.pem" \
    -out "ca-cert.pem" \
    -days 65536 \
    -sha256 \
    -subj "/C=US/CN=root" \
    -addext "basicConstraints = critical,CA:false"

# Generate an intermediate certificate.
openssl req -new -noenc \
    -newkey rsa \
    -pkeyopt rsa_keygen_bits:2048 \
    -keyout "intermediate-key.pem" \
    -out "intermediate.csr" \
    -subj "/C=US/CN=intermediate" \
    -addext "basicConstraints = critical,CA:true"
openssl x509 \
    -days 65536 \
    -req -in "intermediate.csr" \
    -sha256 \
    -CA "ca-cert.pem" \
    -CAkey "ca-key.pem" \
    -CAcreateserial \
    -out "intermediate-cert.pem" \
    -copy_extensions=copyall

# Generate leaf certificate
openssl req -new -noenc \
    -newkey rsa \
    -pkeyopt rsa_keygen_bits:2048 \
    -keyout "leaf-key.pem" \
    -out "leaf.csr" \
    -subj "/C=US/CN=leaf" \
    -addext "subjectAltName = DNS:localhost"
openssl x509 \
    -days 65536 \
    -req -in "leaf.csr" \
    -sha256 \
    -CA "intermediate-cert.pem" \
    -CAkey "intermediate-key.pem" \
    -CAcreateserial \
    -out "leaf-cert.pem" \
    -copy_extensions=copyall

rm *.srl
rm *.csr
rm intermediate-key.pem
rm ca-key.pem
