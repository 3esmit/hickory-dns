//! Real signed DNS replies through the resolver's validating lookup/cache path.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::*;
use crate::{
    config::LookupIpStrategy,
    local_dns::LocalDns,
    proto::{
        dnssec::{
            rdata::{DNSKEY, RRSIG},
            tbs::TBS,
            Algorithm, Proof, SigSigner, SigningKey, TrustAnchor,
        },
        rr::{
            rdata::{A, AAAA},
            DNSClass, RecordData,
        },
        xfer::DnssecDnsHandle,
    },
};

const NAME: &str = "www.example.com.";
const ZONE: &str = "example.com.";

fn signed(record: Record, signer: &SigSigner) -> [Record; 2] {
    let now = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let signature = |bytes| {
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
    let unsigned = signature(Vec::new());
    let tbs = TBS::from_sig(
        record.name(),
        DNSClass::IN,
        &unsigned,
        std::iter::once(&record),
    )
    .unwrap();
    let signature = Record::from_rdata(
        record.name().clone(),
        record.ttl(),
        signature(signer.sign(&tbs).unwrap()).into_rdata(),
    );
    [record, signature]
}

async fn signed_lookup(tampered: bool, trusted: bool) {
    #[cfg(feature = "dnssec-ring")]
    let (key, algorithm) = {
        use crate::proto::dnssec::ring::EcdsaSigningKey;
        let algorithm = Algorithm::ECDSAP256SHA256;
        let encoded = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        (
            EcdsaSigningKey::from_pkcs8(&encoded, algorithm).unwrap(),
            algorithm,
        )
    };
    #[cfg(not(feature = "dnssec-ring"))]
    let (key, algorithm) = {
        use crate::proto::dnssec::openssl::RsaSigningKey;
        let algorithm = Algorithm::RSASHA256;
        (RsaSigningKey::generate(algorithm).unwrap(), algorithm)
    };
    let public = key.to_public_key().unwrap();
    let mut anchor = TrustAnchor::new();
    anchor.insert_trust_anchor(&public);
    let dnskey = DNSKEY::from_key(&public, algorithm);
    let signer = SigSigner::dnssec(
        dnskey.clone(),
        Box::new(key),
        Name::from_ascii(ZONE).unwrap(),
        Duration::from_secs(3600),
    );
    let dnskey = signed(
        Record::from_rdata(Name::from_ascii(ZONE).unwrap(), 60, dnskey.into_rdata()),
        &signer,
    );
    let mut ipv4 = signed(
        Record::from_rdata(
            Name::from_ascii(NAME).unwrap(),
            60,
            RData::A(A::new(93, 184, 215, 14)),
        ),
        &signer,
    );
    let mut ipv6 = signed(
        Record::from_rdata(
            Name::from_ascii(NAME).unwrap(),
            60,
            RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            )),
        ),
        &signer,
    );
    if tampered {
        // Change the signed data, not its signature: neither answer may remain Secure.
        ipv4[0].set_data(RData::A(A::new(93, 184, 215, 15)));
        ipv6[0].set_data(RData::AAAA(AAAA::new(
            0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2d,
        )));
    }
    let expected = [ipv4[0].data().clone(), ipv6[0].data().clone()];
    let server = LocalDns::with_responder(move |request| {
        assert!(request.extensions().as_ref().unwrap().flags().dnssec_ok);
        let query = &request.queries()[0];
        if query.query_type() == RecordType::DS && !trusted {
            assert!([ZONE, "com.", "."]
                .iter()
                .any(|name| query.name() == &Name::from_ascii(name).unwrap()));
            return LocalDns::response(request);
        }
        let records = match query.query_type() {
            RecordType::A => {
                assert_eq!(query.name(), &Name::from_ascii(NAME).unwrap());
                &ipv4
            }
            RecordType::AAAA => {
                assert_eq!(query.name(), &Name::from_ascii(NAME).unwrap());
                &ipv6
            }
            RecordType::DNSKEY => {
                assert_eq!(query.name(), &Name::from_ascii(ZONE).unwrap());
                &dnskey
            }
            other => panic!("unexpected DNSSEC query: {other}"),
        };
        let mut response = LocalDns::response(request);
        // An upstream AD bit is not a substitute for local signature validation.
        response.set_authentic_data(true);
        response.add_answers(records.iter().cloned());
        assert!(response.to_vec().unwrap().len() <= usize::from(request.max_payload()));
        response
    });
    let config = ResolverConfig::from_parts(None, vec![], server.name_servers());
    let options = ResolverOpts {
        validate: true,
        // RSA DNSKEY/RRSIG replies need the advertised EDNS receive size.
        edns0: true,
        cache_size: 0,
        attempts: 0,
        timeout: Duration::from_secs(2),
        use_hosts_file: ResolveHosts::Never,
        ip_strategy: LookupIpStrategy::Ipv4Only,
        ..ResolverOpts::default()
    };
    let provider = TokioConnectionProvider::default();
    let mut resolver = Resolver::new(config.clone(), options.clone(), provider.clone());
    // The public constructor intentionally uses built-in root anchors. Inject the
    // fresh fixture anchor only into the test's private cache/validator pipeline.
    if trusted {
        let pool = NameServerPool::from_config_with_provider(&config, options, provider);
        resolver.client_cache = CachingClient::new(
            0,
            LookupEither::Secure(DnssecDnsHandle::with_trust_anchor(
                RetryDnsHandle::new(pool, 0),
                Arc::new(anchor),
            )),
            false,
        );
    }
    let proof = if tampered || !trusted {
        Proof::Bogus
    } else {
        Proof::Secure
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        for data in &expected {
            for _ in 0..2 {
                let answer = if data.record_type() == RecordType::A {
                    resolver.lookup_ip(NAME).await.unwrap().as_lookup().clone()
                } else {
                    resolver
                        .ipv6_lookup(NAME)
                        .await
                        .unwrap()
                        .as_lookup()
                        .clone()
                };
                assert_eq!(answer.iter().collect::<Vec<_>>(), [data]);
                assert_eq!(answer.record_iter().count(), 1);
                assert_eq!(answer.record_iter().next().unwrap().proof(), proof);
            }
        }
    })
    .await
    .expect("signed resolver test timeout");
    drop(resolver);
    let per_lookup = if trusted {
        vec![NAME, ZONE]
    } else {
        vec![NAME, ZONE, ZONE, "com.", "."]
    };
    server.assert_queries(&per_lookup.repeat(4));
}

#[tokio::test]
async fn test_sec_lookup() {
    signed_lookup(false, true).await;
}

#[tokio::test]
async fn test_sec_lookup_tampered_answers_are_bogus() {
    signed_lookup(true, true).await;
}

#[tokio::test]
async fn test_sec_lookup_default_anchors_do_not_trust_private_key() {
    signed_lookup(false, false).await;
}
