//! Test certificate generation for mTLS integration tests.
//!
//! This module generates a self-signed CA, a server cert, and a client cert
//! in-memory using `rcgen`. The certs are returned as PEM bytes suitable for
//! writing to temp files or passing to rustls/reqwest.
//!
//! # Security
//!
//! These certs are for **testing only**. Never use them in production.

// This module is test-only (behind the `test-certs` feature) and uses
// `expect()` for brevity, which is acceptable here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::OnceLock;

/// A set of test certificates for mTLS: CA, server, and client.
pub struct TestCerts {
    /// The CA certificate (PEM).
    pub ca_cert: Vec<u8>,
    /// The server certificate (PEM).
    pub server_cert: Vec<u8>,
    /// The server private key (PEM).
    pub server_key: Vec<u8>,
    /// The client certificate (PEM).
    pub client_cert: Vec<u8>,
    /// The client private key (PEM).
    pub client_key: Vec<u8>,
}

// rcgen 0.13 uses `Certificate` and `KeyPair` types. We generate once and
// cache via OnceLock to avoid regenerating on every test (slow).
static CERTS: OnceLock<TestCerts> = OnceLock::new();

/// Generates (or returns cached) a set of test certificates for mTLS.
///
/// The CA is self-signed. The server cert has SANs for `central`, `localhost`,
/// and `127.0.0.1`. The client cert has SANs for `relay`, `localhost`, and
/// `127.0.0.1`.
///
/// # Panics
///
/// Panics if cert generation fails (should never happen with valid rcgen
/// usage). This is test-only code.
#[must_use]
pub fn generate_test_certs() -> &'static TestCerts {
    CERTS.get_or_init(generate_certs_inner)
}

/// Inner cert generation logic.
fn generate_certs_inner() -> TestCerts {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    // --- CA ---
    let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "OAC Test CA");
        dn
    };
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().expect("generate CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA cert");

    // --- Server cert (central proxy) ---
    let mut server_params =
        CertificateParams::new(vec!["central".to_string(), "localhost".to_string()])
            .expect("server params");
    server_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "central");
        dn
    };
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    let server_key = KeyPair::generate().expect("generate server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server cert");

    // --- Client cert (relay) ---
    let mut client_params =
        CertificateParams::new(vec!["relay".to_string(), "localhost".to_string()])
            .expect("client params");
    client_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "relay");
        dn
    };
    client_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    let client_key = KeyPair::generate().expect("generate client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("sign client cert");

    TestCerts {
        ca_cert: ca_cert.pem().into_bytes(),
        server_cert: server_cert.pem().into_bytes(),
        server_key: server_key.serialize_pem().into_bytes(),
        client_cert: client_cert.pem().into_bytes(),
        client_key: client_key.serialize_pem().into_bytes(),
    }
}
