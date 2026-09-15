//! Local signed zones for validating clients over real TCP connections.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use hickory_integration::example_authority::create_example;
use hickory_proto::{
    dnssec::{rdata::DNSKEY, Algorithm, SigSigner, SigningKey, TrustAnchor},
    ProtoError,
};
use hickory_server::{
    authority::{Authority, Catalog, ZoneType},
    dnssec::NxProofKind,
    store::in_memory::InMemoryAuthority,
    ServerFuture,
};

pub(super) struct SignedDns {
    server: ServerFuture<Catalog>,
    address: SocketAddr,
    trust_anchor: TrustAnchor,
}

impl SignedDns {
    pub(super) async fn new(proof: NxProofKind) -> Self {
        test_support::subscribe();
        let mut example = create_example();
        let mut authority = InMemoryAuthority::new(
            example.origin().clone().into(),
            example
                .records_get_mut()
                .iter()
                .map(|(key, records)| (key.clone(), records.as_ref().clone()))
                .collect(),
            ZoneType::Primary,
            false,
            Some(proof),
        )
        .unwrap();
        #[cfg(feature = "dnssec-ring")]
        let (key, algorithm) = {
            use hickory_proto::dnssec::ring::EcdsaSigningKey;
            let algorithm = Algorithm::ECDSAP256SHA256;
            let encoded = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
            (
                EcdsaSigningKey::from_pkcs8(&encoded, algorithm).unwrap(),
                algorithm,
            )
        };
        #[cfg(not(feature = "dnssec-ring"))]
        let (key, algorithm) = {
            use hickory_proto::dnssec::openssl::RsaSigningKey;
            let algorithm = Algorithm::RSASHA256;
            (RsaSigningKey::generate(algorithm).unwrap(), algorithm)
        };
        let public_key = key.to_public_key().unwrap();
        let mut trust_anchor = TrustAnchor::new();
        trust_anchor.insert_trust_anchor(&public_key);
        let signer = SigSigner::dnssec(
            DNSKEY::from_key(&public_key, algorithm),
            Box::new(key),
            authority.origin().clone().into(),
            Duration::from_secs(86400),
        );
        authority.add_zone_signing_key_mut(signer).unwrap();
        authority.secure_zone_mut().unwrap();
        let mut catalog = Catalog::new();
        catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let mut server = ServerFuture::new(catalog);
        server.register_listener(listener, Duration::from_secs(5));
        Self {
            server,
            address,
            trust_anchor,
        }
    }

    pub(super) async fn run<F, Fut>(mut self, test: F)
    where
        F: FnOnce(SocketAddr, TrustAnchor) -> Fut,
        Fut: Future<Output = ()>,
    {
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            test(self.address, self.trust_anchor),
        )
        .await;
        tokio::time::timeout(Duration::from_secs(5), self.server.shutdown_gracefully())
            .await
            .expect("signed DNS shutdown timeout")
            .expect("signed DNS shutdown failed");
        result.expect("signed DNS test timeout");
    }
}

pub(super) async fn drive(
    background: impl Future<Output = Result<(), ProtoError>>,
    queries: impl Future<Output = ()>,
) {
    // The driver is polled with the queries and dropped on completion or cancellation.
    tokio::select! {
        _ = queries => {}
        result = background => panic!("DNS driver ended before queries: {result:?}"),
    }
}
