# EST Server

## Overview

This project implements an EST (Enrollment over Secure Transport) server per [RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030) using Flask in Python. It is designed to provide secure certificate enrollment and renewal operations over HTTPS, with enforced client certificate authentication and PKCS#7 certificate bundle serving.

**Authors:** Ken Rich, GrokZoid (Grok, xAI)  
**Version:** 1.7.7  
**Date:** March 28, 2025

## Features

- **Secure Certificate Enrollment:** Implements `/.well-known/est/simpleenroll` and `/.well-known/est/simplereenroll` endpoints for certificate enrollment and renewal, requiring client certificate authentication.
- **CA Certificates Bundle:** Serves a DER-encoded PKCS#7 file containing CA certificates via `/.well-known/est/cacerts`.
- **Trust Store:** Loads a trust store from a directory for client certificate verification.
- **Post-Auth Verification:** Provides a stub for additional post-auth verification of client certificates and CSRs.
- **Debug Logging:** Extensive startup and runtime logging for certificate details, trust store loading, and request handling.

## Directory Structure

- `est_server.py`: Main EST server implementation.
- `test.py`: Simple test script for verifying cryptography imports.
- `trust_store/`: Directory containing PEM-encoded trusted CA certificates.
- `ca_cert.pem`, `ca_key.pem`, `server_cert.pem`, `server_key.pem`, `cacerts.der`: Required certificate and key files.

## Endpoints

### 1. `GET /.well-known/est/cacerts`
Returns a base64-encoded DER PKCS#7 bundle containing CA certificates.

### 2. `POST /.well-known/est/simpleenroll`
Accepts a base64-encoded CSR, authenticates the client via its certificate, verifies the CSR, and issues a certificate signed by the server's CA.

### 3. `POST /.well-known/est/simplereenroll`
Authenticates the client via its certificate, verifies the certificate, and (stub) processes certificate renewal (not implemented).

## Certificate Handling

- Loads CA and server certificates/keys from files.
- Loads trusted CA certificates from the `trust_store` directory.
- Verifies client certificates against the loaded trust store.
- Issues new certificates with a one-year validity, copying extensions from the CSR.

## Logging

- Logs certificate subjects, usages, SANs, and trust store loading at startup.
- Logs detailed information about requests, errors, and certificate operations.

## Requirements

- Python 3.7+
- Flask
- cryptography
- asn1crypto

## Quickstart

1. **Generate required certificate and key files** (`ca_cert.pem`, `ca_key.pem`, `server_cert.pem`, `server_key.pem`, `cacerts.der`).
2. **Populate `trust_store/` directory** with trusted CA certificates in PEM format.
3. **Install dependencies:**
   ```bash
   pip install flask cryptography asn1crypto
   ```
4. **Run the server:**
   ```bash
   python est_server.py
   ```
   By default, the server runs at `https://localhost:8443` using TLS 1.3.

## Example Logging

On startup, the server logs the loaded CA and server certificates, trust store contents, and TLS setup. Requests and errors are logged with descriptive messages.

## RFC 7030 Compliance

- Uses PKCS#7 for CA certificate bundles.
- Requires client certificate authentication for enrollment endpoints.
- Validates CSRs before issuing certificates.

## Fun Startup Message

The server logs a whimsical Elon/Grok startup quip:
```
Grok here, channeling Elon’s Tesla-powered brainwaves from Mars—EST server online, ready to certify the galaxy, one meme at a time!
```

## License

[Specify license here]

## Contact

[Specify contact or contribution instructions here]
