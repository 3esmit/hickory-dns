//! Local DoT tests retain authentication without modifying the system trust store.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use test_support::tls::TestIdentity;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

use crate::{
    config::{LookupIpStrategy, NameServerConfigGroup, ResolveHosts, ResolverConfig, ResolverOpts},
    name_server::{ConnectionProvider, TokioConnectionProvider},
    proto::{
        op::{Message, MessageType, Query},
        rr::{
            rdata::{A, AAAA},
            Name, RData, Record, RecordType,
        },
    },
    Resolver,
};

const NAME: &str = "www.example.com.";
const SERVER_NAME: &str = "ns.example.test";

fn acceptor(identity: &TestIdentity) -> tokio_rustls::TlsAcceptor {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
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
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

fn config(listener: &TcpListener, name: &str) -> ResolverConfig {
    let address = listener.local_addr().unwrap();
    ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_tls(&[address.ip()], address.port(), name.into(), true),
    )
}

fn options() -> ResolverOpts {
    ResolverOpts {
        cache_size: 0,
        attempts: 0,
        timeout: Duration::from_secs(2),
        use_hosts_file: ResolveHosts::Never,
        ip_strategy: LookupIpStrategy::Ipv4Only,
        ..ResolverOpts::default()
    }
}

#[cfg(feature = "dns-over-rustls")]
type TestProvider = TokioConnectionProvider;
#[cfg(not(feature = "dns-over-rustls"))]
use custom_roots::TestProvider;

fn resolver(config: ResolverConfig, root: &TestIdentity) -> (Resolver<TestProvider>, TestProvider) {
    #[cfg(feature = "dns-over-rustls")]
    let (config, provider) = {
        let mut config = config;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(root.ca.to_der().unwrap()))
            .unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        // Match the default DoT configuration; authentication must not depend on sending SNI.
        client.enable_sni = false;
        config.set_tls_client_config(Arc::new(client));
        (config, TestProvider::default())
    };
    #[cfg(not(feature = "dns-over-rustls"))]
    let provider = TestProvider::new(root.ca.to_der().unwrap());
    (Resolver::new(config, options(), provider.clone()), provider)
}

async fn round_trip(server_name: &str) {
    let identity = TestIdentity::new(server_name).unwrap();
    let acceptor = acceptor(&identity);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (resolver, provider) = resolver(config(&listener, server_name), &identity);
    let records = [
        RData::A(A::new(93, 184, 215, 14)),
        RData::AAAA(AAAA::new(
            0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
        )),
    ];
    let (done, finished) = oneshot::channel();
    let serving = async {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        for data in &records {
            // Cache disabled: repeat each lookup over the same authenticated connection.
            for _ in 0..2 {
                let length = usize::from(tls.read_u16().await.unwrap());
                assert!((12..=4096).contains(&length));
                let mut bytes = vec![0; length];
                tls.read_exact(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes).unwrap();
                let query = Query::query(Name::from_ascii(NAME).unwrap(), data.record_type());
                assert_eq!(request.message_type(), MessageType::Query);
                assert_eq!(request.queries(), std::slice::from_ref(&query));
                let mut response = Message::new();
                response
                    .set_id(request.id())
                    .set_message_type(MessageType::Response)
                    .add_query(query)
                    .add_answer(Record::from_rdata(
                        Name::from_ascii(NAME).unwrap(),
                        60,
                        data.clone(),
                    ));
                let bytes = response.to_vec().unwrap();
                tls.write_u16(u16::try_from(bytes.len()).unwrap())
                    .await
                    .unwrap();
                tls.write_all(&bytes).await.unwrap();
                tls.flush().await.unwrap();
            }
        }
        finished.await.unwrap();
    };
    let querying = async {
        for data in &records {
            for _ in 0..2 {
                match data {
                    RData::A(address) => {
                        let answer = resolver.lookup_ip(NAME).await.unwrap();
                        assert_eq!(
                            answer.iter().collect::<Vec<_>>(),
                            [std::net::IpAddr::V4(address.0)]
                        );
                    }
                    RData::AAAA(address) => {
                        let answer = resolver.ipv6_lookup(NAME).await.unwrap();
                        assert_eq!(answer.iter().collect::<Vec<_>>(), [address]);
                    }
                    _ => unreachable!("fixture contains only address records"),
                }
            }
        }
        done.send(()).unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(serving, querying);
    })
    .await
    .expect("local TLS resolver timeout");
    drop(resolver);
    #[cfg(not(feature = "dns-over-rustls"))]
    provider.shutdown().await;
    drop(provider);
}

async fn rejection<P: ConnectionProvider>(
    listener: TcpListener,
    identity: &TestIdentity,
    resolver: Resolver<P>,
) {
    let acceptor = acceptor(identity);
    let serving = async {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor.accept(tcp).await
    };
    let (server, client) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(serving, resolver.lookup(NAME, RecordType::A))
    })
    .await
    .expect("TLS rejection timeout");
    assert!(
        server.is_err(),
        "invalid certificate must fail the TLS handshake"
    );
    let error = client.expect_err("invalid certificate must not resolve");
    // Native TLS diagnostics are platform-specific. Check the transport error
    // boundary rather than English certificate text; a timeout is not a rejection.
    match error.proto().map(|error| error.kind()) {
        Some(crate::proto::ProtoErrorKind::Io(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        }
        _ => panic!("expected TLS handshake failure, got {error:?}"),
    }
}

#[tokio::test]
async fn test_local_tls_dns_name_and_ip() {
    round_trip(SERVER_NAME).await;
    round_trip("127.0.0.1").await;
}

#[tokio::test]
async fn test_local_tls_rejects_wrong_name() {
    let identity = TestIdentity::new(SERVER_NAME).unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (resolver, provider) = resolver(config(&listener, "wrong.example.test"), &identity);
    rejection(listener, &identity, resolver).await;
    #[cfg(not(feature = "dns-over-rustls"))]
    provider.shutdown().await;
    drop(provider);
}

#[tokio::test]
async fn test_local_tls_rejects_untrusted_root() {
    let identity = TestIdentity::new(SERVER_NAME).unwrap();
    let other = TestIdentity::new(SERVER_NAME).unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (resolver, provider) = resolver(config(&listener, SERVER_NAME), &other);
    rejection(listener, &identity, resolver).await;
    #[cfg(not(feature = "dns-over-rustls"))]
    provider.shutdown().await;
    drop(provider);
}

#[tokio::test]
async fn test_local_tls_default_provider_rejects_private_ca() {
    let identity = TestIdentity::new(SERVER_NAME).unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let resolver = Resolver::new(
        config(&listener, SERVER_NAME),
        options(),
        TokioConnectionProvider::default(),
    );
    rejection(listener, &identity, resolver).await;
}

#[cfg(not(feature = "dns-over-rustls"))]
mod custom_roots {
    use crate::{
        config::{NameServerConfig, ResolverOpts},
        name_server::ConnectionProvider,
        proto::{
            runtime::{TokioRuntimeProvider, TokioTime},
            xfer::{DnsExchange, DnsMultiplexer, Protocol},
            ProtoError,
        },
    };
    use std::{
        future::Future,
        io,
        pin::Pin,
        sync::{Arc, Mutex},
    };
    use tokio::task::JoinSet;

    /// Native TLS and OpenSSL expose custom roots through their protocol builders,
    /// not NameServerConfig. Exercise those through the public customization seam.
    #[derive(Clone)]
    pub(super) struct TestProvider {
        root: Vec<u8>,
        tasks: Arc<Mutex<JoinSet<Result<(), ProtoError>>>>,
    }

    impl TestProvider {
        pub(super) fn new(root: Vec<u8>) -> Self {
            Self {
                root,
                tasks: Arc::new(Mutex::new(JoinSet::new())),
            }
        }

        pub(super) async fn shutdown(&self) {
            let mut tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
            tasks.abort_all();
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok(result) => result.unwrap(),
                    Err(error) => assert!(error.is_cancelled(), "TLS driver panicked: {error}"),
                }
            }
        }
    }

    impl ConnectionProvider for TestProvider {
        type Conn = DnsExchange;
        type FutureConn = Pin<Box<dyn Future<Output = Result<DnsExchange, ProtoError>> + Send>>;
        type RuntimeProvider = TokioRuntimeProvider;

        fn new_connection(
            &self,
            config: &NameServerConfig,
            options: &ResolverOpts,
        ) -> io::Result<Self::FutureConn> {
            assert_eq!(config.protocol, Protocol::Tls);
            let runtime = TokioRuntimeProvider::default();
            #[cfg(feature = "dns-over-native-tls")]
            let mut builder = {
                let mut builder = crate::proto::native_tls::TlsClientStreamBuilder::new(runtime);
                builder.add_ca(
                    tokio_native_tls::native_tls::Certificate::from_der(&self.root).unwrap(),
                );
                builder
            };
            #[cfg(not(feature = "dns-over-native-tls"))]
            let mut builder = {
                let mut builder = crate::proto::openssl::TlsClientStreamBuilder::new(runtime);
                builder.add_ca_der(&self.root)?;
                builder
            };
            if let Some(address) = config.bind_addr {
                builder.bind_addr(address);
            }
            let (stream, handle) =
                builder.build(config.socket_addr, config.tls_dns_name.clone().unwrap());
            let multiplexer = DnsMultiplexer::with_timeout(stream, handle, options.timeout, None);
            let tasks = self.tasks.clone();
            Ok(Box::pin(async move {
                let (exchange, background) =
                    DnsExchange::connect::<_, _, TokioTime>(multiplexer).await?;
                tasks.lock().unwrap().spawn(background);
                Ok(exchange)
            }))
        }
    }
}
