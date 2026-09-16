//! Fresh, in-memory identities for local TLS transport tests.

use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509,
    },
};

/// A fresh CA and one-day server identity held only in memory.
pub struct TestIdentity {
    pub ca: X509,
    pub cert: X509,
    pub key: PKey<Private>,
}

impl TestIdentity {
    /// Creates an independently signed identity for a DNS name or IP address.
    pub fn new(server_name: &str) -> Result<Self, ErrorStack> {
        let ca_key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut ca_name = X509NameBuilder::new()?;
        ca_name.append_entry_by_text("CN", "Hickory test CA")?;
        let ca_name = ca_name.build();
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(1)?;

        let mut ca = X509::builder()?;
        ca.set_version(2)?;
        let ca_serial = BigNum::from_u32(1)?.to_asn1_integer()?;
        ca.set_serial_number(&ca_serial)?;
        ca.set_subject_name(&ca_name)?;
        ca.set_issuer_name(&ca_name)?;
        ca.set_pubkey(&ca_key)?;
        ca.set_not_before(&not_before)?;
        ca.set_not_after(&not_after)?;
        ca.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
        ca.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
        ca.sign(&ca_key, MessageDigest::sha256())?;
        let ca = ca.build();

        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", server_name)?;
        let name = name.build();
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        let cert_serial = BigNum::from_u32(2)?.to_asn1_integer()?;
        cert.set_serial_number(&cert_serial)?;
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(ca.subject_name())?;
        cert.set_pubkey(&key)?;
        cert.set_not_before(&not_before)?;
        cert.set_not_after(&not_after)?;
        cert.append_extension(BasicConstraints::new().critical().build()?)?;
        cert.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        cert.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
        let mut names = SubjectAlternativeName::new();
        if server_name.parse::<std::net::IpAddr>().is_ok() {
            names.ip(server_name);
        } else {
            names.dns(server_name);
        }
        cert.append_extension(names.build(&cert.x509v3_context(Some(&ca), None))?)?;
        cert.sign(&ca_key, MessageDigest::sha256())?;

        Ok(Self {
            ca,
            cert: cert.build(),
            key,
        })
    }
}
