# TODO: RFC 7030 Compliance & Improvements

This document tracks tasks to improve the EST server implementation and align it more closely with RFC 7030.

## 1. Endpoint Coverage

- [ ] Implement `/csrattrs` endpoint (CSR attributes, RFC 7030 section 3.4).
- [ ] Implement `/serverkeygen` endpoint (server-side key generation, RFC 7030 section 4).

## 2. Re-enrollment

- [ ] Complete logic for `/simplereenroll` endpoint (currently returns 501).
  - Verify the presented certificate.
  - Accept and process a new CSR for reenrollment.

## 3. Client Certificate Authentication

- [ ] Ensure reliable access to client certificate data (document requirements for deployment behind TLS proxy, or enhance direct access).

## 4. CSR and Policy Validation

- [ ] Add stricter CSR validation:
  - Validate subject fields (e.g., CN, SAN).
  - Restrict or sanitize requested extensions.
  - Document and enforce server-side policy checks.

## 5. Error Handling

- [ ] Standardize error messages and HTTP response codes per RFC 7030.
- [ ] Provide richer error bodies for client parsing.

## 6. TLS Configuration

- [ ] Consider setting `verify_mode` to `CERT_REQUIRED` for endpoints requiring client authentication.
- [ ] Document rationale if `CERT_OPTIONAL` is retained.

## 7. Security Enhancements

- [ ] Implement rate limiting and replay protection for sensitive endpoints.
- [ ] Add audit logging for enrollment and certificate issuance events.
- [ ] Ensure robust file loading and error handling for all cert/key/trust store files.

## 8. Documentation

- [ ] Expand README with API usage examples (curl, openssl, etc.).
- [ ] Document deployment requirements for client certificate authentication.

## 9. Logging

- [ ] Make log levels configurable.
- [ ] Sanitize logs to avoid leaking sensitive information in production.

---

_Last updated: 2025-07-11_
