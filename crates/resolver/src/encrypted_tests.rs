//! Authenticated local resolver round trips, independent of public DNS services.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ClientConfig,
};
use test_support::tls::TestIdentity;
use tokio::sync::oneshot;

use crate::{
    config::{LookupIpStrategy, NameServerConfigGroup, ResolveHosts, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    proto::{
        op::{Message, MessageType, Query},
        rr::{
            rdata::{A, AAAA},
            Name, RData, Record, RecordType,
        },
        xfer::Protocol,
        ProtoError,
    },
    TokioResolver,
};

const NAME: &str = "www.example.com.";
#[cfg(any(feature = "dns-over-h3", feature = "dns-over-https-rustls"))]
const PATH: &str = "/dns-query";
const COUNT: usize = 4;

fn query(index: usize) -> Query {
    Query::query(
        Name::from_ascii(NAME).unwrap(),
        if index < 2 {
            RecordType::A
        } else {
            RecordType::AAAA
        },
    )
}

fn reply(bytes: &[u8], index: usize) -> Vec<u8> {
    let request = Message::from_vec(bytes).unwrap();
    assert_eq!(request.message_type(), MessageType::Query);
    assert_eq!(request.queries(), &[query(index)]);
    let data = if index < 2 {
        RData::A(A::new(93, 184, 215, 14))
    } else {
        RData::AAAA(AAAA::new(
            0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
        ))
    };
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .add_query(query(index))
        .add_answer(Record::from_rdata(query(index).name().clone(), 60, data));
    response.to_vec().unwrap()
}

fn identity_parts(
    identity: &TestIdentity,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (
        vec![CertificateDer::from(identity.cert.to_der().unwrap())],
        PrivatePkcs8KeyDer::from(identity.key.private_key_to_pkcs8().unwrap()).into(),
    )
}

fn resolver(
    address: SocketAddr,
    server_name: &str,
    root: &TestIdentity,
    protocol: Protocol,
) -> TokioResolver {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(root.ca.to_der().unwrap()))
        .unwrap();
    let mut client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    // Preserve the SNI-enabled QUIC client configuration tested by the public-service case.
    client.enable_sni = true;
    let ips = [address.ip()];
    let servers = match protocol {
        #[cfg(feature = "dns-over-https-rustls")]
        Protocol::Https => {
            NameServerConfigGroup::from_ips_https(&ips, address.port(), server_name.into(), true)
        }
        #[cfg(feature = "dns-over-h3")]
        Protocol::H3 => {
            NameServerConfigGroup::from_ips_h3(&ips, address.port(), server_name.into(), true)
        }
        #[cfg(feature = "dns-over-quic")]
        Protocol::Quic => {
            NameServerConfigGroup::from_ips_quic(&ips, address.port(), server_name.into(), true)
        }
        _ => panic!("unsupported test protocol"),
    }
    .with_client_config(Arc::new(client));
    TokioResolver::new(
        ResolverConfig::from_parts(None, vec![], servers),
        ResolverOpts {
            cache_size: 0,
            // This fixture accepts one connection; surface its certificate failure directly.
            attempts: 0,
            timeout: Duration::from_secs(2),
            use_hosts_file: ResolveHosts::Never,
            ip_strategy: LookupIpStrategy::Ipv4Only,
            ..ResolverOpts::default()
        },
        TokioConnectionProvider::default(),
    )
}

async fn check_queries(resolver: &TokioResolver) {
    for index in 0..COUNT {
        if index < 2 {
            let response = resolver.lookup_ip(NAME).await.unwrap();
            assert_eq!(
                response.iter().collect::<Vec<_>>(),
                [IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))]
            );
        } else {
            let response = resolver.ipv6_lookup(NAME).await.unwrap();
            assert_eq!(
                response.iter().map(|address| address.0).collect::<Vec<_>>(),
                [Ipv6Addr::new(
                    0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c
                )]
            );
        }
    }
}

async fn rejected<T>(
    accept: impl Future<Output = Result<Option<T>, ProtoError>>,
    resolver: TokioResolver,
    expected: &str,
) {
    let (server, client) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(accept, resolver.lookup_ip(NAME))
    })
    .await
    .expect("certificate rejection timeout");
    assert!(
        server.is_err(),
        "server must reject the failed TLS handshake"
    );
    let error = client.expect_err("untrusted peer must not resolve");
    assert!(
        format!("{error:?}").contains(expected),
        "unexpected rejection: {error:?}"
    );
}

#[cfg(feature = "dns-over-https-rustls")]
fn https_acceptor(identity: &TestIdentity) -> tokio_rustls::TlsAcceptor {
    let (cert, key) = identity_parts(identity);
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(cert, key)
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

#[cfg(feature = "dns-over-https-rustls")]
pub(crate) async fn https_round_trip(server_name: &str) {
    use crate::proto::http::Version;
    use futures_util::{stream::FuturesUnordered, StreamExt};
    let identity = TestIdentity::new(server_name).unwrap();
    let acceptor = https_acceptor(&identity);
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let resolver = resolver(
        listener.local_addr().unwrap(),
        server_name,
        &identity,
        Protocol::Https,
    );
    let (done, mut finished) = oneshot::channel();
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
                    assert!(accepted < COUNT);
                    let index = accepted;
                    accepted += 1;
                    requests.push(async move {
                        let bytes = crate::proto::h2::h2_server::message_from(Some(server_name.into()), PATH.into(), request).await.unwrap();
                        let bytes = reply(&bytes, index);
                        let headers = crate::proto::http::response::new(Version::Http2, bytes.len()).unwrap();
                        response.send_response(headers, false).unwrap().send_data(bytes.into(), true).unwrap();
                    });
                }
            }
        }
        assert_eq!(accepted, COUNT);
        assert_eq!(completed, COUNT);
    };
    let querying = async {
        check_queries(&resolver).await;
        done.send(()).unwrap();
    };
    // The connection and request futures stay owned and polled until all replies are observed.
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(serving, querying);
    })
    .await
    .expect("local HTTPS resolver timeout");
}

#[cfg(feature = "dns-over-https-rustls")]
pub(crate) async fn https_rejects_identity(wrong_name: bool) {
    let identity = TestIdentity::new("ns.example.test").unwrap();
    let unrelated = TestIdentity::new("ns.example.test").unwrap();
    let acceptor = https_acceptor(&identity);
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let (name, root, expected) = if wrong_name {
        ("wrong.example.test", &identity, "NotValidForName")
    } else {
        ("ns.example.test", &unrelated, "BadSignature")
    };
    let resolver = resolver(listener.local_addr().unwrap(), name, root, Protocol::Https);
    rejected(
        async {
            let (tcp, _) = listener.accept().await?;
            acceptor
                .accept(tcp)
                .await
                .map(Some)
                .map_err(ProtoError::from)
        },
        resolver,
        expected,
    )
    .await;
}

#[cfg(feature = "dns-over-quic")]
pub(crate) async fn quic_round_trip(server_name: &str) {
    use crate::proto::quic::QuicServer;
    let identity = TestIdentity::new(server_name).unwrap();
    let (cert, key) = identity_parts(&identity);
    let mut server = QuicServer::new(([127, 0, 0, 1], 0).into(), cert, key)
        .await
        .unwrap();
    let resolver = resolver(
        server.local_addr().unwrap(),
        server_name,
        &identity,
        Protocol::Quic,
    );
    let (done, finished) = oneshot::channel();
    let serving = async {
        let (mut connection, _) = server.next().await.unwrap().unwrap();
        for index in 0..COUNT {
            let mut stream = connection.next().await.unwrap().unwrap();
            let request = stream.receive_bytes().await.unwrap();
            stream
                .send_bytes(reply(&request, index).into())
                .await
                .unwrap();
            stream.finish().await.unwrap();
        }
        finished.await.unwrap();
    };
    let querying = async {
        check_queries(&resolver).await;
        done.send(()).unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(serving, querying);
    })
    .await
    .expect("local QUIC resolver timeout");
}

#[cfg(feature = "dns-over-quic")]
pub(crate) async fn quic_rejects_identity(wrong_name: bool) {
    use crate::proto::quic::QuicServer;
    let identity = TestIdentity::new("ns.example.test").unwrap();
    let unrelated = TestIdentity::new("ns.example.test").unwrap();
    let (cert, key) = identity_parts(&identity);
    let mut server = QuicServer::new(([127, 0, 0, 1], 0).into(), cert, key)
        .await
        .unwrap();
    let (name, root, expected) = if wrong_name {
        ("wrong.example.test", &identity, "NotValidForName")
    } else {
        ("ns.example.test", &unrelated, "BadSignature")
    };
    let resolver = resolver(server.local_addr().unwrap(), name, root, Protocol::Quic);
    rejected(server.next(), resolver, expected).await;
}

#[cfg(feature = "dns-over-h3")]
pub(crate) async fn h3_round_trip(server_name: &str) {
    use crate::proto::{h3::h3_server::H3Server, http::Version};
    use bytes::Buf;
    let identity = TestIdentity::new(server_name).unwrap();
    let (cert, key) = identity_parts(&identity);
    let mut server = H3Server::new(([127, 0, 0, 1], 0).into(), cert, key)
        .await
        .unwrap();
    let resolver = resolver(
        server.local_addr().unwrap(),
        server_name,
        &identity,
        Protocol::H3,
    );
    let (done, finished) = oneshot::channel();
    let serving = async {
        let (mut connection, _) = server.accept().await.unwrap().unwrap();
        for index in 0..COUNT {
            let (request, mut stream) = connection.accept().await.unwrap().unwrap();
            crate::proto::http::request::verify(Version::Http3, Some(server_name), PATH, &request)
                .unwrap();
            let mut bytes = Vec::new();
            while let Some(mut frame) = stream.recv_data().await.unwrap() {
                assert!(bytes.len() + frame.remaining() <= 4096);
                bytes.extend_from_slice(&frame.copy_to_bytes(frame.remaining()));
            }
            let response = reply(&bytes, index);
            stream
                .send_response(
                    crate::proto::http::response::new(Version::Http3, response.len()).unwrap(),
                )
                .await
                .unwrap();
            stream.send_data(response.into()).await.unwrap();
            stream.finish().await.unwrap();
        }
        finished.await.unwrap();
    };
    let querying = async {
        check_queries(&resolver).await;
        done.send(()).unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(serving, querying);
    })
    .await
    .expect("local H3 resolver timeout");
}

#[cfg(feature = "dns-over-h3")]
pub(crate) async fn h3_rejects_identity(wrong_name: bool) {
    use crate::proto::h3::h3_server::H3Server;
    let identity = TestIdentity::new("ns.example.test").unwrap();
    let unrelated = TestIdentity::new("ns.example.test").unwrap();
    let (cert, key) = identity_parts(&identity);
    let mut server = H3Server::new(([127, 0, 0, 1], 0).into(), cert, key)
        .await
        .unwrap();
    let (name, root, expected) = if wrong_name {
        ("wrong.example.test", &identity, "NotValidForName")
    } else {
        ("ns.example.test", &unrelated, "BadSignature")
    };
    let resolver = resolver(server.local_addr().unwrap(), name, root, Protocol::H3);
    rejected(server.accept(), resolver, expected).await;
}
