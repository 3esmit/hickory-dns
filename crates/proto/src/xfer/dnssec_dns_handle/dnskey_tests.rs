//! Authentication of DNSKEY sets through the validating handle and DNS wire format.

use super::*;
use crate::{
    dnssec::{tbs::TBS, DigestType, SigSigner, SigningKey},
    op::MessageType,
    rr::{rdata::A, DNSClass},
};
use futures_executor::block_on;
use std::sync::Mutex;

fn signer(name: &Name) -> SigSigner {
    #[cfg(feature = "dnssec-ring")]
    let (key, algorithm) = {
        use crate::dnssec::ring::EcdsaSigningKey;
        let algorithm = Algorithm::ECDSAP256SHA256;
        let encoded = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        (
            EcdsaSigningKey::from_pkcs8(&encoded, algorithm).unwrap(),
            algorithm,
        )
    };
    #[cfg(not(feature = "dnssec-ring"))]
    let (key, algorithm) = {
        use crate::dnssec::openssl::RsaSigningKey;
        let algorithm = Algorithm::RSASHA256;
        (RsaSigningKey::generate(algorithm).unwrap(), algorithm)
    };
    let public = key.to_public_key().unwrap();
    SigSigner::dnssec(
        DNSKEY::from_key(&public, algorithm),
        Box::new(key),
        name.clone(),
        std::time::Duration::from_secs(3600),
    )
}

fn dnskey(signer: &SigSigner) -> Record {
    Record::from_rdata(
        signer.signer_name().clone(),
        300,
        signer.to_dnskey().unwrap().into_rdata(),
    )
}

fn signature(records: &[Record], signer: &SigSigner) -> Record {
    let record = &records[0];
    let now = current_time();
    let rrsig = |bytes| {
        RRSIG::new(
            record.record_type(),
            signer.algorithm(),
            record.name().num_labels(),
            record.ttl(),
            now + 3600,
            now - 60,
            signer.calculate_key_tag().unwrap(),
            signer.signer_name().clone(),
            bytes,
        )
    };
    let unsigned = rrsig(Vec::new());
    let tbs = TBS::from_sig(record.name(), DNSClass::IN, &unsigned, records.iter()).unwrap();
    Record::from_rdata(
        record.name().clone(),
        60,
        rrsig(signer.sign(&tbs).unwrap()).into_rdata(),
    )
}

#[derive(Clone)]
struct SignedResponses {
    records: Arc<Vec<Record>>,
    queries: Arc<Mutex<Vec<Query>>>,
}

impl DnsHandle for SignedResponses {
    type Response = stream::Iter<std::vec::IntoIter<Result<DnsResponse, ProtoError>>>;

    fn send<R: Into<DnsRequest>>(&self, request: R) -> Self::Response {
        let request = request.into();
        let query = request.queries()[0].clone();
        assert!(request.extensions().as_ref().unwrap().flags().dnssec_ok);
        self.queries.lock().unwrap().push(query.clone());
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_authoritative(true)
            // Upstream AD must not authenticate injected keys.
            .set_authentic_data(true)
            .add_query(query.clone());
        for record in self.records.iter().filter(|record| {
            record.name() == query.name()
                && (record.record_type() == query.query_type()
                    || record.try_borrow::<RRSIG>().map_or(false, |rrsig| {
                        rrsig.data().type_covered() == query.query_type()
                    }))
        }) {
            response.add_answer(record.clone());
        }
        assert!(!response.answers().is_empty(), "unexpected query: {query}");
        stream::iter(vec![DnsResponse::from_buffer(response.to_vec().unwrap())])
    }
}

#[derive(Clone, Copy)]
enum KeysetSignature {
    Trusted,
    Untrusted,
    Missing,
    TrustedSubset,
}

fn validate_keyset(delegated: bool, signature_kind: KeysetSignature, single_key: bool) {
    let zone = Name::from_ascii("example.").unwrap();
    let trusted = signer(&zone);
    let untrusted = signer(&zone);
    let parent = signer(&Name::root());
    let mut anchors = TrustAnchor::new();
    let anchor = if delegated { &parent } else { &trusted };
    anchors.insert_trust_anchor(&anchor.key().to_public_key().unwrap());

    let mut keys = vec![dnskey(&trusted)];
    if !single_key {
        keys.push(dnskey(&untrusted));
    }
    let mut records = keys.clone();
    match signature_kind {
        KeysetSignature::Trusted => records.push(signature(&keys, &trusted)),
        KeysetSignature::Untrusted => records.push(signature(&keys, &untrusted)),
        KeysetSignature::Missing => {}
        KeysetSignature::TrustedSubset => records.push(signature(&keys[..1], &trusted)),
    }
    if delegated {
        let parent_key = dnskey(&parent);
        let trusted_key = trusted.to_dnskey().unwrap();
        let ds = Record::from_rdata(
            zone.clone(),
            300,
            DS::new(
                trusted_key.calculate_key_tag().unwrap(),
                trusted_key.algorithm(),
                DigestType::SHA256,
                trusted_key
                    .to_digest(&zone, DigestType::SHA256)
                    .unwrap()
                    .as_ref()
                    .to_owned(),
            )
            .into_rdata(),
        );
        records.push(signature(std::slice::from_ref(&parent_key), &parent));
        records.push(parent_key);
        records.push(signature(std::slice::from_ref(&ds), &parent));
        records.push(ds);
    }
    let answer = Record::from_rdata(
        Name::from_ascii("www.example.").unwrap(),
        300,
        RData::A(A::new(192, 0, 2, 1)),
    );
    // The second key can sign answers only if the first authenticates the key set.
    let answer_signer = if single_key { &trusted } else { &untrusted };
    records.push(signature(std::slice::from_ref(&answer), answer_signer));
    records.push(answer.clone());
    let queries = Arc::new(Mutex::new(Vec::new()));
    let handle = DnssecDnsHandle::with_trust_anchor(
        SignedResponses {
            records: Arc::new(records),
            queries: Arc::clone(&queries),
        },
        Arc::new(anchors),
    );
    for query in [
        Query::query(zone.clone(), RecordType::DNSKEY),
        Query::query(answer.name().clone(), RecordType::A),
    ] {
        let response = block_on(
            handle
                .lookup(query.clone(), DnsRequestOptions::default())
                .first_answer(),
        )
        .unwrap();
        let data: Vec<_> = response
            .answers()
            .iter()
            .filter(|record| record.record_type() == query.query_type())
            .collect();
        assert_eq!(
            data.len(),
            if query.query_type() == RecordType::DNSKEY {
                keys.len()
            } else {
                1
            }
        );
        for (index, record) in data.into_iter().enumerate() {
            let expected = if single_key || matches!(signature_kind, KeysetSignature::Trusted) {
                Proof::Secure
            } else if query.query_type() == RecordType::DNSKEY && index == 0 {
                Proof::Secure
            } else {
                Proof::Indeterminate
            };
            if matches!(signature_kind, KeysetSignature::Trusted) || single_key {
                assert_eq!(record.proof(), expected, "{query}: {record}");
            } else if query.query_type() == RecordType::DNSKEY && index == 0 {
                assert_eq!(record.proof(), Proof::Secure, "{query}: {record}");
            } else {
                assert_ne!(record.proof(), Proof::Secure, "{query}: {record}");
            }
            if matches!(signature_kind, KeysetSignature::Trusted) {
                assert!(record.ttl() <= 300, "validated TTL must include RRSIG TTL");
            }
        }
    }
    let queries = queries.lock().unwrap();
    assert_eq!(
        queries
            .iter()
            .any(|query| query.query_type() == RecordType::DS),
        delegated
    );
}

#[test]
fn trust_anchor_cannot_promote_attacker_signed_keys() {
    validate_keyset(false, KeysetSignature::Untrusted, false);
}

#[test]
fn ds_key_cannot_promote_attacker_signed_keys() {
    validate_keyset(true, KeysetSignature::Untrusted, false);
}

#[test]
fn trust_anchor_cannot_promote_unsigned_keys() {
    validate_keyset(false, KeysetSignature::Missing, false);
}

#[test]
fn ds_key_cannot_promote_unsigned_keys() {
    validate_keyset(true, KeysetSignature::Missing, false);
}

#[test]
fn trust_anchor_signature_must_cover_all_keys() {
    validate_keyset(false, KeysetSignature::TrustedSubset, false);
}

#[test]
fn ds_key_signature_must_cover_all_keys() {
    validate_keyset(true, KeysetSignature::TrustedSubset, false);
}

#[test]
fn trust_anchor_authenticates_key_rollover() {
    validate_keyset(false, KeysetSignature::Trusted, false);
}

#[test]
fn ds_key_authenticates_key_rollover() {
    validate_keyset(true, KeysetSignature::Trusted, false);
}

#[test]
fn independently_trusted_unsigned_key_remains_secure() {
    validate_keyset(false, KeysetSignature::Missing, true);
}
