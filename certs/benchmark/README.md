# Public benchmark identity

These files are deliberately public test fixtures, including the private key.
They provide TLS encryption for synthetic benchmarks, **not trustworthy server
identity**. Anyone can impersonate a server using this certificate.

- `server.pem`: self-signed RSA-2048/SHA-256 certificate, valid from 2020 to 2040.
- `server.key`: matching, deliberately public, unencrypted test key.
- `server.der`: the same certificate in DER form; CMake hashes it for the client pin.
- `server.pfx`: the same certificate/key for Windows HTTP.sys provisioning.

The PFX password is `winlin-public-benchmark`. It is only an import-format
convenience, not a secret or access credential.

Use only on isolated benchmark networks with synthetic data. Never reuse this key
for a real identity, install the certificate as a trusted root, or replace these
fixtures with real credentials.

Custom Linux `--cert`/`--key`, Windows `-CertificateThumbprint`, and client
`--fingerprint` options remain available. Existing Linux certificate/key files in
the selected state directory take precedence over these defaults.
