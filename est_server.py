#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EST Server script
Version: 1.7.7
Authors: Ken Rich, GrokZoid (Grok, xAI)
Date: March 28, 2025
Description:
This script implements an EST (Enrollment over Secure Transport) server per RFC 7030 using Flask. Updated to enforce client certificate authentication for /simpleenroll and /simplereenroll, fixed /simpleenroll to process CSRs and return certificates, added a post-auth verification stub with CSR input, uses a proper server certificate with serverAuth EKU, logs certificate subjects and purposes on startup, fixed SAN logging for IPv4Address, added an Elon/Grok startup quip, serves a DER-encoded PKCS#7 file for /cacerts per RFC 7030, and loads a trust database from a directory for client certificate verification. Uses cafile for trust store loading with added debug logging.
"""

from flask import Flask, request, Response
import ssl
import base64
import logging
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime
import os
from asn1crypto import cms

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Certificate files
CA_CERT_FILE = "ca_cert.pem"
CA_KEY_FILE = "ca_key.pem"
SERVER_CERT_FILE = "server_cert.pem"
SERVER_KEY_FILE = "server_key.pem"
TRUST_STORE_DIR = "trust_store"
CACERTS_DER_FILE = "cacerts.der"

for f in [CA_CERT_FILE, CA_KEY_FILE, SERVER_CERT_FILE, SERVER_KEY_FILE, CACERTS_DER_FILE]:
    if not os.path.exists(f):
        logger.error("%s not found. Please generate it first.", f)
        raise FileNotFoundError(f"{f} missing")

if not os.path.isdir(TRUST_STORE_DIR):
    logger.error("Trust store directory %s not found.", TRUST_STORE_DIR)
    raise FileNotFoundError(f"Trust store directory {TRUST_STORE_DIR} missing")

with open(CA_CERT_FILE, 'r') as f:
    ca_cert_pem = f.read()
with open(CA_KEY_FILE, 'r') as f:
    ca_key_pem = f.read()
with open(SERVER_CERT_FILE, 'r') as f:
    server_cert_pem = f.read()
with open(SERVER_KEY_FILE, 'r') as f:
    server_key_pem = f.read()
with open(CACERTS_DER_FILE, 'rb') as f:
    cacerts_der = f.read()

ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('ascii'))
ca_key = serialization.load_pem_private_key(ca_key_pem.encode('ascii'), password=None)
server_cert = x509.load_pem_x509_certificate(server_cert_pem.encode('ascii'))

# Load trust store from directory
trust_store_certs = []
for filename in os.listdir(TRUST_STORE_DIR):
    if filename.endswith(".pem"):
        filepath = os.path.join(TRUST_STORE_DIR, filename)
        try:
            with open(filepath, 'rb') as f:
                pem_data = f.read()
            if not pem_data.strip().startswith(b"-----BEGIN CERTIFICATE-----"):
                logger.warning("File %s does not contain a valid PEM certificate, skipping", filename)
                continue
            cert = x509.load_pem_x509_certificate(pem_data)
            trust_store_certs.append(cert)
            logger.info("Loaded trust store cert from %s: Subject=%s", filename, cert.subject)
        except Exception as e:
            logger.warning("Failed to load %s into trust store: %s", filename, str(e))

if not trust_store_certs:
    logger.error("No valid certificates found in trust store directory %s", TRUST_STORE_DIR)
    raise ValueError(f"No valid certificates in {TRUST_STORE_DIR}")

def log_cert_details(cert, purpose):
    logger.info("Certificate for %s:", purpose)
    logger.info("  Subject: %s", cert.subject)
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        logger.info("  Key Usage: %s", ", ".join([k for k, v in ku.value.__dict__.items() if v]))
    except x509.ExtensionNotFound:
        logger.info("  Key Usage: Not specified")
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        logger.info("  Extended Key Usage: %s", ", ".join([oid._name for oid in eku.value]))
    except x509.ExtensionNotFound:
        logger.info("  Extended Key Usage: Not specified")
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        ip_addresses = [str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)]
        san_values = dns_names + ip_addresses
        logger.info("  SAN: %s", ", ".join(san_values))
    except x509.ExtensionNotFound:
        logger.info("  SAN: Not specified")

log_cert_details(ca_cert, "CA certificate")
log_cert_details(server_cert, "Server certificate")

def verify_client_post_auth(client_cert, csr):
    logger.debug("Running post-auth verification - Client cert: %s, CSR subject: %s", client_cert.subject, csr.subject)
    return True

def get_client_cert():
    cert_pem = request.environ.get('SSL_CLIENT_CERT')
    logger.debug("SSL_CLIENT_CERT from environ: %s", cert_pem if cert_pem else "None")
    logger.debug("Relevant environ keys: %s", {k: v for k, v in request.environ.items() if 'SSL' in k or 'CERT' in k})
    if not cert_pem:
        logger.debug("No client certificate provided")
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
        logger.debug("Client certificate loaded: Subject=%s, Issuer=%s", cert.subject, cert.issuer)
        return cert
    except Exception as e:
        logger.exception("Error loading client certificate: %s", str(e))
        return None

def verify_client_cert(client_cert):
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        if now < client_cert.not_valid_before_utc or now > client_cert.not_valid_after_utc:
            logger.warning("Client certificate is not within validity period")
            return False
        
        issuer_matches = [trust_cert for trust_cert in trust_store_certs if client_cert.issuer == trust_cert.subject]
        if not issuer_matches:
            logger.warning("Client certificate issuer %s not found in trust store", client_cert.issuer)
            return False
        
        logger.info("Client certificate issuer verified against trust store: %s", issuer_matches[0].subject)
        return True
    except Exception as e:
        logger.warning("Client certificate verification failed: %s", str(e))
        return False

@app.route('/.well-known/est/cacerts', methods=['GET'])
def cacerts():
    logger.info("Serving CA certificates from cacerts.der")
    cacerts_b64 = base64.b64encode(cacerts_der).decode('ascii')
    return Response(cacerts_b64, mimetype='application/pkcs7-mime; smime-type=certs-only')

@app.route('/.well-known/est/simpleenroll', methods=['POST'])
def simpleenroll():
    client_cert = get_client_cert()
    if not client_cert:
        logger.warning("Client authentication failed: No certificate provided")
        return Response("Client certificate required", status=401, mimetype='text/plain')

    if not verify_client_cert(client_cert):
        logger.warning("Client certificate verification failed: %s", client_cert.subject)
        return Response("Unauthorized: Invalid client certificate", status=401, mimetype='text/plain')

    try:
        csr_data = request.data
        if not csr_data:
            logger.warning("No CSR provided in request")
            return Response("Bad Request: No CSR provided", status=400, mimetype='text/plain')
        
        # Decode base64 CSR from client
        csr_bytes = base64.b64decode(csr_data)
        csr = x509.load_pem_x509_csr(csr_bytes)
        logger.info("Received CSR from client: %s", csr.subject)

        if not csr.is_signature_valid:
            logger.warning("CSR signature is invalid")
            return Response("Bad Request: Invalid CSR signature", status=400, mimetype='text/plain')

        # Post-auth verification with CSR
        if not verify_client_post_auth(client_cert, csr):
            logger.warning("Post-auth verification failed for client: %s", client_cert.subject)
            return Response("Unauthorized: Additional verification failed", status=401, mimetype='text/plain')

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        )
        for ext in csr.extensions:
            cert_builder = cert_builder.add_extension(ext.value, critical=ext.critical)

        cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
        logger.info("Issued certificate for %s", csr.subject)

        # Convert cert to DER for asn1crypto
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        pkcs7 = cms.ContentInfo({
            'content_type': 'signed_data',
            'content': cms.SignedData({
                'version': 'v1',
                'digest_algorithms': [],
                'encap_content_info': {'content_type': 'data'},
                'certificates': [cms.CertificateChoices.load(cert_der)],
                'signer_infos': []  # Certs-only mode
            })
        })
        pkcs7_der = pkcs7.dump()
        pkcs7_b64 = base64.b64encode(pkcs7_der).decode('ascii')
        logger.debug("Returning PKCS#7 (DER, hex): %s", pkcs7_der.hex()[:100] + "..." if len(pkcs7_der) > 50 else pkcs7_der.hex())

        return Response(
            pkcs7_b64,
            mimetype='application/pkcs7-mime; smime-type=certs-only'
        )
    except base64.binascii.Error as e:
        logger.exception("Error decoding base64 CSR: %s", str(e))
        return Response("Bad Request: Invalid CSR encoding", status=400, mimetype='text/plain')
    except Exception as e:
        logger.exception("Error processing CSR: %s", str(e))
        return Response("Bad Request: Invalid CSR", status=400, mimetype='text/plain')

@app.route('/.well-known/est/simplereenroll', methods=['POST'])
def simplereenroll():
    client_cert = get_client_cert()
    if not client_cert:
        logger.warning("Client authentication failed: No certificate provided")
        return Response("Client certificate required", status=401, mimetype='text/plain')
    
    if not verify_client_cert(client_cert):
        logger.warning("Client certificate verification failed: %s", client_cert.subject)
        return Response("Unauthorized: Invalid client certificate", status=401, mimetype='text/plain')
    
    logger.info("Reenrollment requested (not implemented)")
    return Response("Reenrollment not implemented", status=501, mimetype='text/plain')

if __name__ == "__main__":
    logger.debug("Entering main block")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    logger.debug("SSLContext created")
    context.load_cert_chain(certfile=SERVER_CERT_FILE, keyfile=SERVER_KEY_FILE)
    logger.debug("Server cert chain loaded")
    for filename in os.listdir(TRUST_STORE_DIR):
        if filename.endswith(".pem"):
            filepath = os.path.join(TRUST_STORE_DIR, filename)
            logger.debug("Loading trust store cert from file: %s", filepath)
            context.load_verify_locations(cafile=filepath)
    logger.debug("Trust store certs loaded")
    context.verify_mode = ssl.CERT_OPTIONAL
    logger.debug("Verify mode set to CERT_OPTIONAL")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    logger.debug("Minimum TLS version set to TLSv1_3")

    logger.info("Grok here, channeling Elon’s Tesla-powered brainwaves from Mars—EST server online, ready to certify the galaxy, one meme at a time!")
    logger.info("Starting EST server on https://localhost:8443 with TLS version: %s", context.minimum_version.name)
    logger.info("Trust store loaded with %d certificates", len(trust_store_certs))
    logger.debug("Starting Flask app.run")
    app.run(host='localhost', port=8443, ssl_context=context, threaded=True)
    logger.debug("Flask app.run completed (this should not appear unless server stops)")


