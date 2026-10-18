# Sample reports

- `example.com/`: live public TLS handshake snapshot; observations depend on time, local trust store and network path.
- `local-test/localhost/`: real local OpenSSL server on port 19443, restricted to TLS 1.2+, with a one-day self-signed certificate. Verbose text report includes raw handshakes. This was a controlled integration fixture, not a public endpoint.
- Console transcripts are plain text (colours are emitted only on a TTY).

WARN / UNTESTED is intentional when this OpenSSL cannot offer an obsolete protocol/cipher. Revocation response observation is not a fully verified revocation check.
