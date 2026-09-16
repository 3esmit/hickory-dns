use super::*;
use hickory_resolver::{
    config::{LookupIpStrategy, ResolveHosts},
    proto::rr::{rdata::AAAA, RData},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NAME: &str = "www.example.com.";
const IPV4: Ipv4Addr = Ipv4Addr::new(93, 184, 215, 14);
const IPV6: Ipv6Addr = Ipv6Addr::new(
    0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
);

fn options(strategy: LookupIpStrategy) -> ResolverOpts {
    let mut options = ResolverOpts::default();
    options.ip_strategy = strategy;
    options.use_hosts_file = ResolveHosts::Never;
    options.attempts = 0;
    options.cache_size = 0;
    options.timeout = Duration::from_secs(2);
    options
}

#[tokio::test]
async fn test_custom_provider_udp() {
    for (server, strategy, expected) in [
        (
            local_dns::LocalDns::new(),
            LookupIpStrategy::Ipv4Only,
            IpAddr::V4(IPV4),
        ),
        (
            local_dns::LocalDns::with_answer(RData::AAAA(AAAA(IPV6))),
            LookupIpStrategy::Ipv6Only,
            IpAddr::V6(IPV6),
        ),
    ] {
        let resolver = Resolver::new(
            ResolverConfig::from_parts(None, vec![], server.name_servers()),
            options(strategy),
            GenericConnector::new(PrintProvider::default()),
        );
        for _ in 0..2 {
            let response = lookup(&resolver).await;
            assert_eq!(response.iter().collect::<Vec<_>>(), [expected]);
        }
        drop(resolver);
        server.assert_queries(&[NAME, NAME]);
    }
}

#[cfg(feature = "dns-over-https-rustls")]
#[tokio::test]
async fn test_custom_provider_https() {
    use futures_util::{stream::FuturesUnordered, StreamExt};
    use hickory_resolver::{
        config::NameServerConfigGroup,
        proto::{
            op::{Message, MessageType, Query},
            rr::{rdata::A, Name, Record, RecordType},
        },
    };
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use test_support::tls::TestIdentity;

    const SERVER_NAME: &str = "ns.example.test";
    let identity = TestIdentity::new(SERVER_NAME).unwrap();
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(identity.cert.to_der().unwrap())],
        PrivatePkcs8KeyDer::from(identity.key.private_key_to_pkcs8().unwrap()).into(),
    )
    .unwrap();
    let mut server_config = server_config;
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(identity.ca.to_der().unwrap()))
        .unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let servers = NameServerConfigGroup::from_ips_https(
        &[address.ip()],
        address.port(),
        SERVER_NAME.into(),
        true,
    )
    .with_client_config(Arc::new(client_config));
    let resolver = Resolver::new(
        ResolverConfig::from_parts(None, vec![], servers),
        options(LookupIpStrategy::Ipv4Only),
        GenericConnector::new(PrintProvider::default()),
    );
    let (done, mut finished) = tokio::sync::oneshot::channel();
    let serving = async {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let mut requests = FuturesUnordered::new();
        let mut accepted = 0;
        let mut completed = 0;
        loop {
            tokio::select! {
                biased;
                Some(()) = requests.next(), if !requests.is_empty() => completed += 1,
                result = &mut finished => { result.unwrap(); break; }
                incoming = connection.accept() => {
                    let (request, mut response) = incoming.unwrap().unwrap();
                    assert!(accepted < 4);
                    let index = accepted;
                    accepted += 1;
                    requests.push(async move {
                        let bytes = hickory_resolver::proto::h2::h2_server::message_from(Some(SERVER_NAME.into()), "/dns-query".into(), request).await.unwrap();
                        let message = Message::from_vec(&bytes).unwrap();
                        let query = Query::query(Name::from_ascii(NAME).unwrap(), if index < 2 { RecordType::A } else { RecordType::AAAA });
                        assert_eq!(message.message_type(), MessageType::Query);
                        assert_eq!(message.queries(), std::slice::from_ref(&query));
                        let mut answer = Message::new();
                        answer.set_id(message.id()).set_message_type(MessageType::Response).add_query(query)
                            .add_answer(Record::from_rdata(Name::from_ascii(NAME).unwrap(), 60, if index < 2 { RData::A(A(IPV4)) } else { RData::AAAA(AAAA(IPV6)) }));
                        let bytes = answer.to_vec().unwrap();
                        let headers = hickory_resolver::proto::http::response::new(hickory_resolver::proto::http::Version::Http2, bytes.len()).unwrap();
                        response.send_response(headers, false).unwrap().send_data(bytes.into(), true).unwrap();
                    });
                }
            }
        }
        assert_eq!(accepted, 4);
        assert_eq!(completed, 4);
    };
    let querying = async {
        for _ in 0..2 {
            let response = lookup(&resolver).await;
            assert_eq!(response.iter().collect::<Vec<_>>(), [IpAddr::V4(IPV4)]);
        }
        for _ in 0..2 {
            let response = resolver.ipv6_lookup(NAME).await.unwrap();
            assert_eq!(
                response.iter().map(|address| address.0).collect::<Vec<_>>(),
                [IPV6]
            );
        }
        done.send(()).unwrap();
    };
    // Keep the connection/request futures owned and driven until the last reply is observed.
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(serving, querying);
    })
    .await
    .expect("custom provider HTTPS timeout");
}
