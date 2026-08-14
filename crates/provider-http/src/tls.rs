//! Real HTTPS + SPKI pin enforcement (DR-09 §2, §7; closes v0.1-review NEW
//! P1 #1: the SPKI pin was defined but never enforced).
//!
//! A custom `rustls::client::ServerCertVerifier` that (1) delegates to the
//! WebPKI verifier and (2) when a `spki_sha256` pin is set, hashes the peer's
//! SubjectPublicKeyInfo and compares. A mismatch fails closed with E0310
//! BEFORE the credential/body is sent (GW-23).

use crate::error::TransportError;
use orbit_adapter::types::TlsPinPolicy;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Build the rustls client config with the optional SPKI-pinning verifier.
pub fn client_config(tls: &TlsPinPolicy) -> Result<Arc<rustls::ClientConfig>, TransportError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }

    // Build the base config with the populated roots.
    let base = rustls::ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();

    // If a pin is set, wrap the WebPKI verifier (built over the same roots)
    // with the SPKI-pinning check.
    if let Some(pin) = tls.spki_sha256.as_deref().filter(|p| !p.is_empty()) {
        let default = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| TransportError::TlsMismatch(format!("verifier build: {e}")))?;
        let mut config = base;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(PinningVerifier {
                inner: default,
                expected_spki: pin.to_string(),
            }));
        Ok(Arc::new(config))
    } else {
        Ok(Arc::new(base))
    }
}

/// A `ServerCertVerifier` that WebPKI-verifies AND checks the SPKI pin.
#[derive(Debug)]
struct PinningVerifier {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    expected_spki: String,
}

impl rustls::client::danger::ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Delegate to WebPKI first (this catches expired/revoked/wrong-host).
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Then check the SPKI pin.
        let spki_der = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("parse leaf cert: {e}")))?;
        let digest = hex::encode(Sha256::digest(spki_der.1.public_key().raw));
        if digest == self.expected_spki {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "SPKI pin mismatch: got {digest}, expected {} (E0310)",
                self.expected_spki
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Extract the SPKI SHA-256 from a DER certificate (tests compute the pin).
pub fn spki_sha256_of(der: &[u8]) -> Result<String, TransportError> {
    let parsed = x509_parser::parse_x509_certificate(der)
        .map_err(|e| TransportError::TlsMismatch(format!("parse cert: {e}")))?;
    Ok(hex::encode(Sha256::digest(parsed.1.public_key().raw)))
}
