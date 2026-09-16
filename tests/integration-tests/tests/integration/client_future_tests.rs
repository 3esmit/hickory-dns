use std::{
    str::FromStr,
    sync::{Arc, Mutex as StdMutex},
};

use futures::{Future, FutureExt, TryFutureExt};
use test_support::subscribe;
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    runtime::Runtime,
};

use hickory_client::{
    client::{Client, ClientHandle},
    ClientErrorKind,
};
use hickory_integration::{
    example_authority::create_example, NeverReturnsClientStream, TestClientStream, GOOGLE_V6,
    TEST3_V4,
};
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_proto::{
    dnssec::SigSigner,
    xfer::{DnsExchangeBackground, DnsMultiplexer},
};
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_proto::{
    dnssec::{openssl::RsaSigningKey, rdata::DNSSECRData, Algorithm, SigningKey},
    runtime::TokioTime,
};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        rdata::{
            opt::{EdnsCode, EdnsOption},
            A,
        },
        DNSClass, Name, RData, Record, RecordSet, RecordType,
    },
    runtime::TokioRuntimeProvider,
    tcp::TcpClientStream,
    udp::UdpClientStream,
    xfer::FirstAnswer,
    DnsHandle, ProtoError,
};
use hickory_server::authority::{Authority, Catalog};

#[test]
fn test_query_nonet() {
    subscribe();

    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);

    let io_loop = Runtime::new().unwrap();
    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = Client::new(stream, sender, None);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query(&mut client));
}

#[tokio::test]
async fn test_query_udp_ipv4() {
    let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let server = async {
        let mut buffer = [0; 4096];
        for index in 0..3 {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let response = local_query_response(&buffer[..length], index == 2);
            assert_eq!(
                socket.send_to(&response, peer).await.unwrap(),
                response.len()
            );
        }
    };
    let client = async {
        let stream = UdpClientStream::builder(address, TokioRuntimeProvider::new()).build();
        let (client, background) = Client::connect(stream).await.unwrap();
        check_local_queries(client, background, true).await;
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(server, client);
    })
    .await
    .expect("local UDP query timeout");
}

#[test]
#[ignore]
fn test_query_udp_ipv6() {
    let io_loop = Runtime::new().unwrap();
    let stream = UdpClientStream::builder(GOOGLE_V6, TokioRuntimeProvider::new()).build();
    let client = Client::connect(stream);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query_edns(&mut client));
}

#[tokio::test]
async fn test_query_tcp_ipv4() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (done, finished) = tokio::sync::oneshot::channel();
    let server = async {
        // Both queries must arrive on the same accepted connection.
        let (mut socket, _) = listener.accept().await.unwrap();
        for _ in 0..2 {
            let length = usize::from(socket.read_u16().await.unwrap());
            assert!(length <= 4096);
            let mut buffer = vec![0; length];
            socket.read_exact(&mut buffer).await.unwrap();
            let response = local_query_response(&buffer, false);
            socket
                .write_u16(response.len().try_into().unwrap())
                .await
                .unwrap();
            socket.write_all(&response).await.unwrap();
        }
        // Keep the socket alive until the client has consumed the final reply.
        finished.await.unwrap();
    };
    let client = async {
        let (stream, sender) =
            TcpClientStream::new(address, None, None, TokioRuntimeProvider::new());
        let (client, background) = Client::new(stream, sender, None).await.unwrap();
        check_local_queries(client, background, false).await;
        done.send(()).unwrap();
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(server, client);
    })
    .await
    .expect("local TCP query timeout");
}

pub(super) fn local_query_response(bytes: &[u8], subnet: bool) -> Vec<u8> {
    let request = Message::from_vec(bytes).unwrap();
    let name = Name::from_ascii("WWW.example.com.").unwrap();
    assert_eq!(request.message_type(), MessageType::Query);
    assert_eq!(request.op_code(), OpCode::Query);
    assert_eq!(
        request.queries(),
        &[Query::query(name.clone(), RecordType::A)]
    );
    assert!(request.queries()[0].name().eq_case(&name));
    let edns = request.extensions().as_ref().expect("EDNS request");
    assert_eq!(edns.version(), 0);
    if subnet {
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(
            edns.option(EdnsCode::Subnet),
            Some(&EdnsOption::Subnet("1.2.0.0/16".parse().unwrap()))
        );
    } else {
        assert!(edns.option(EdnsCode::Subnet).is_none());
    }
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_response_code(ResponseCode::NoError)
        .add_query(request.queries()[0].clone())
        .add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A::new(93, 184, 215, 14)),
        ))
        .set_edns(edns.clone());
    response.to_vec().unwrap()
}

async fn check_local_queries(
    mut client: Client,
    background: impl Future<Output = Result<(), ProtoError>>,
    subnet: bool,
) {
    let queries = async {
        test_query(&mut client).await;
        test_query(&mut client).await;
        if subnet {
            test_query_edns(&mut client).await;
        }
    };
    // Poll the driver with the queries, then deliberately drop it at test completion.
    // Neither this driver nor the owning server future is detached on timeout/panic.
    tokio::select! {
        _ = queries => {}
        result = background => panic!("client driver ended before queries: {result:?}"),
    }
}

#[test]
#[ignore]
fn test_query_tcp_ipv6() {
    let io_loop = Runtime::new().unwrap();
    let (stream, sender) = TcpClientStream::new(GOOGLE_V6, None, None, TokioRuntimeProvider::new());
    let client = Client::new(stream, sender, None);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.block_on(test_query(&mut client));
    io_loop.block_on(test_query(&mut client));
}

#[tokio::test]
#[cfg(feature = "dns-over-https-rustls")]
async fn test_query_https() {
    use hickory_proto::h2::HttpsClientStreamBuilder;
    use hickory_server::ServerFuture;
    use rustls::{
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore,
    };
    use test_support::tls::TestIdentity;

    const ALPN_H2: &[u8] = b"h2";
    const SERVER_NAME: &str = "ns.example.test";

    let identity = TestIdentity::new(SERVER_NAME).unwrap();
    let mut root_store = RootCertStore::empty();
    root_store
        .add(CertificateDer::from(identity.ca.to_der().unwrap()))
        .unwrap();
    let unrelated = TestIdentity::new(SERVER_NAME).unwrap();
    let mut unrelated_roots = RootCertStore::empty();
    unrelated_roots
        .add(CertificateDer::from(unrelated.ca.to_der().unwrap()))
        .unwrap();

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);
    let mut server = ServerFuture::new(catalog);
    server
        .register_https_listener(
            listener,
            std::time::Duration::from_secs(5),
            (
                vec![CertificateDer::from(identity.cert.to_der().unwrap())],
                PrivatePkcs8KeyDer::from(identity.key.private_key_to_pkcs8().unwrap()).into(),
            ),
            Some(SERVER_NAME.to_owned()),
            "/dns-query".to_owned(),
        )
        .unwrap();

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for (roots, requested_name, certificate_error) in [
            (root_store.clone(), SERVER_NAME, None),
            (root_store, "wrong.example.test", Some("NotValidForName")),
            // The unrelated CA has the same issuer name, but a different signing key.
            (unrelated_roots, SERVER_NAME, Some("BadSignature")),
        ] {
            let mut client_config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            client_config.alpn_protocols.push(ALPN_H2.to_vec());
            let https_builder = HttpsClientStreamBuilder::with_client_config(
                Arc::new(client_config),
                TokioRuntimeProvider::new(),
            );
            let connection = Client::connect(https_builder.build(
                address,
                requested_name.to_owned(),
                "/dns-query".to_owned(),
            ))
            .await;
            if let Some(expected) = certificate_error {
                let error = connection.err().expect("invalid certificate accepted");
                assert!(error.to_string().contains(expected), "{error}");
            } else {
                let (client, background) = connection.unwrap();
                check_local_queries(client, background, false).await;
            }
        }
    })
    .await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        server.shutdown_gracefully(),
    )
    .await
    .expect("local HTTPS shutdown timeout")
    .expect("local HTTPS shutdown failed");
    result.expect("local HTTPS query timeout");
}

#[cfg(test)]
fn test_query(client: &mut Client) -> impl Future<Output = ()> {
    let name = Name::from_ascii("WWW.example.com").unwrap();

    client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .map_ok(move |response| {
            println!("response records: {response:?}");
            assert!(response
                .queries()
                .first()
                .expect("expected query")
                .name()
                .eq_case(&name));

            let record = &response.answers()[0];
            assert_eq!(record.name(), &name);
            assert_eq!(record.record_type(), RecordType::A);
            assert_eq!(record.dns_class(), DNSClass::IN);

            if let RData::A(address) = record.data() {
                assert_eq!(address, &A::new(93, 184, 215, 14))
            } else {
                panic!();
            }
        })
        .map(|r: Result<_, _>| r.expect("query failed"))
}

#[cfg(test)]
fn test_query_edns(client: &mut Client) -> impl Future<Output = ()> {
    let name = Name::from_ascii("WWW.example.com").unwrap();
    let mut edns = Edns::new();
    // garbage subnet value, but lets check
    edns.options_mut()
        .insert(EdnsOption::Subnet("1.2.0.0/16".parse().unwrap()));

    // TODO: write builder
    let mut msg = Message::new();
    msg.add_query({
        let mut query = Query::query(name.clone(), RecordType::A);
        query.set_query_class(DNSClass::IN);
        query
    })
    .set_id(rand::random::<u16>())
    .set_message_type(MessageType::Query)
    .set_op_code(OpCode::Query)
    .set_recursion_desired(true)
    .set_edns(edns)
    .extensions_mut()
    .as_mut()
    .map(|edns| edns.set_max_payload(1232).set_version(0));

    client
        .send(msg)
        .first_answer()
        .map_ok(move |response| {
            println!("response records: {response:?}");
            assert!(response
                .queries()
                .first()
                .expect("expected query")
                .name()
                .eq_case(&name));

            let record = &response.answers()[0];
            assert_eq!(record.name(), &name);
            assert_eq!(record.record_type(), RecordType::A);
            assert_eq!(record.dns_class(), DNSClass::IN);
            assert!(response.extensions().is_some());
            assert_eq!(
                response
                    .extensions()
                    .as_ref()
                    .unwrap()
                    .option(EdnsCode::Subnet)
                    .unwrap(),
                &EdnsOption::Subnet("1.2.0.0/16".parse().unwrap())
            );
            if let RData::A(address) = *record.data() {
                assert_eq!(address, A::new(93, 184, 215, 14))
            } else {
                panic!();
            }
        })
        .map(|r: Result<_, _>| r.expect("query failed"))
}

#[test]
fn test_notify() {
    let io_loop = Runtime::new().unwrap();
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);

    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = Client::new(stream, sender, None);
    let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    let name = Name::from_str("ping.example.com").unwrap();

    let message =
        io_loop.block_on(client.notify(name, DNSClass::IN, RecordType::A, None::<RecordSet>));
    assert!(message.is_ok());
    let message = message.unwrap();
    assert_eq!(
        message.response_code(),
        ResponseCode::NotImp,
        "the catalog must support Notify now, update this"
    );
}

// update tests
//

/// create a client with a sig0 section
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[allow(clippy::type_complexity)]
async fn create_sig0_ready_client() -> (
    (
        Client,
        DnsExchangeBackground<DnsMultiplexer<TestClientStream>, TokioTime>,
    ),
    Name,
) {
    use hickory_proto::dnssec::rdata::KEY;
    use hickory_server::store::sqlite::SqliteAuthority;

    let authority = create_example();
    let mut authority = SqliteAuthority::new(authority, true, false);
    let origin = authority.origin().clone();

    let trusted_name = Name::from_str("trusted.example.com").unwrap();

    let key = RsaSigningKey::generate(Algorithm::RSASHA256).unwrap();
    let pub_key = key.to_public_key().unwrap();
    let sig0_key = KEY::new_sig0key(&pub_key, Algorithm::RSASHA256);

    let signer = SigSigner::sig0(sig0_key.clone(), Box::new(key), trusted_name.clone());

    // insert the KEY for the trusted.example.com
    let auth_key = Record::from_rdata(
        trusted_name,
        Duration::minutes(5).whole_seconds() as u32,
        RData::DNSSEC(DNSSECRData::KEY(sig0_key)),
    );
    authority.upsert_mut(auth_key, 0);

    // setup the catalog
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);

    let signer = Arc::new(signer);
    let (stream, sender) = TestClientStream::new(Arc::new(StdMutex::new(catalog)));
    let client = Client::new(stream, sender, Some(signer))
        .await
        .expect("failed to get new Client");

    (client, origin.into())
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_create() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // create a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record;
    record.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = io_loop
        .block_on(client.create(record, origin))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_create_multi() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // create a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let mut record2 = record.clone();
    record2.set_data(RData::A(A::new(100, 10, 100, 11)));
    let record2 = record2;

    let mut rrset = RecordSet::from(record.clone());
    rrset.insert(record2.clone(), 0);
    let rrset = rrset;

    let result = io_loop
        .block_on(client.create(rrset.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result.answers().contains(&record));
    assert!(result.answers().contains(&record2));

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = io_loop
        .block_on(client.create(rrset, origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    let mut record = record;
    record.set_data(RData::A(A::new(101, 11, 101, 12)));

    let result = io_loop
        .block_on(client.create(record, origin))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_append() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // append a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), true))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), false))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record2 = record.clone();
    record2.set_data(RData::A(A::new(101, 11, 101, 11)));
    let record2 = record2;

    let result = io_loop
        .block_on(client.append(record2.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result.answers().contains(&record));
    assert!(result.answers().contains(&record2));

    // show that appending the same thing again is ok, but doesn't add any records
    let result = io_loop
        .block_on(client.append(record.clone(), origin, true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_append_multi() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // append a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), true))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), false))
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record2 = record.clone();
    record2.set_data(RData::A(A::new(101, 11, 101, 11)));
    let mut record3 = record.clone();
    record3.set_data(RData::A(A::new(101, 11, 101, 12)));

    // build the append set
    let mut rrset = RecordSet::from(record2.clone());
    rrset.insert(record3.clone(), 0);

    let result = io_loop
        .block_on(client.append(rrset, origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 3);

    assert!(result.answers().contains(&record));
    assert!(result.answers().contains(&record2));
    assert!(result.answers().contains(&record3));

    // show that appending the same thing again is ok, but doesn't add any records
    // TODO: technically this is a test for the Server, not client...
    let result = io_loop
        .block_on(client.append(record.clone(), origin, true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 3);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_compare_and_swap() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // create a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.set_data(RData::A(A::new(101, 11, 101, 11)));
    let new = new;

    let result = io_loop
        .block_on(client.compare_and_swap(current.clone(), new.clone(), origin.clone()))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().contains(&new));
    assert!(!result.answers().contains(&current));

    // check the it fails if tried again.
    let mut not = new.clone();
    not.set_data(RData::A(A::new(102, 12, 102, 12)));
    let not = not;

    let result = io_loop
        .block_on(client.compare_and_swap(current, not.clone(), origin))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().contains(&new));
    assert!(!result.answers().contains(&not));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_compare_and_swap_multi() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // create a record
    let mut current = RecordSet::with_ttl(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );

    let current1 = current
        .new_record(&RData::A(A::new(100, 10, 100, 10)))
        .clone();
    let current2 = current
        .new_record(&RData::A(A::new(100, 10, 100, 11)))
        .clone();
    let current = current;

    let result = io_loop
        .block_on(client.create(current.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut new = RecordSet::with_ttl(current.name().clone(), current.record_type(), current.ttl());
    let new1 = new.new_record(&RData::A(A::new(100, 10, 101, 10))).clone();
    let new2 = new.new_record(&RData::A(A::new(100, 10, 101, 11))).clone();
    let new = new;

    let result = io_loop
        .block_on(client.compare_and_swap(current.clone(), new.clone(), origin.clone()))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(result.answers().contains(&new1));
    assert!(result.answers().contains(&new2));
    assert!(!result.answers().contains(&current1));
    assert!(!result.answers().contains(&current2));

    // check the it fails if tried again.
    let mut not = new1.clone();
    not.set_data(RData::A(A::new(102, 12, 102, 12)));
    let not = not;

    let result = io_loop
        .block_on(client.compare_and_swap(current, not.clone(), origin))
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = io_loop
        .block_on(client.query(new.name().clone(), new.dns_class(), new.record_type()))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(result.answers().contains(&new1));
    assert!(!result.answers().contains(&not));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_by_rdata() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // append a record
    let record1 = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = io_loop
        .block_on(client.delete_by_rdata(record1.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(record1.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record2 = record1.clone();
    record2.set_data(RData::A(A::new(101, 11, 101, 11)));
    let result = io_loop
        .block_on(client.append(record2.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_by_rdata(record2, origin))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record1.name().clone(),
            record1.dns_class(),
            record1.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result.answers().contains(&record1));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_by_rdata_multi() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );

    let record1 = rrset
        .new_record(&RData::A(A::new(100, 10, 100, 10)))
        .clone();
    let record2 = rrset
        .new_record(&RData::A(A::new(100, 10, 100, 11)))
        .clone();
    let record3 = rrset
        .new_record(&RData::A(A::new(100, 10, 100, 12)))
        .clone();
    let record4 = rrset
        .new_record(&RData::A(A::new(100, 10, 100, 13)))
        .clone();
    let rrset = rrset;

    // first check the must_exist option
    let result = io_loop
        .block_on(client.delete_by_rdata(rrset.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(rrset, origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // append a record
    let mut rrset = RecordSet::with_ttl(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
    );

    let record1 = rrset.new_record(record1.data()).clone();
    let record3 = rrset.new_record(record3.data()).clone();
    let rrset = rrset;

    let result = io_loop
        .block_on(client.append(rrset.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_by_rdata(rrset, origin))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record1.name().clone(),
            record1.dns_class(),
            record1.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
    assert!(!result.answers().contains(&record1));
    assert!(result.answers().contains(&record2));
    assert!(!result.answers().contains(&record3));
    assert!(result.answers().contains(&record4));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_rrset() {
    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = io_loop
        .block_on(client.delete_rrset(record.clone(), origin.clone()))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    record.set_data(RData::A(A::new(101, 11, 101, 11)));
    let result = io_loop
        .block_on(client.append(record.clone(), origin.clone(), true))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_rrset(record.clone(), origin))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        ))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_all() {
    use hickory_proto::rr::rdata::AAAA;

    let io_loop = Runtime::new().unwrap();
    let ((mut client, bg), origin) = io_loop.block_on(create_sig0_ready_client());
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = io_loop
        .block_on(client.delete_all(record.name().clone(), origin.clone(), DNSClass::IN))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    record.set_data(RData::AAAA(AAAA::new(1, 2, 3, 4, 5, 6, 7, 8)));
    let result = io_loop
        .block_on(client.create(record.clone(), origin.clone()))
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = io_loop
        .block_on(client.delete_all(record.name().clone(), origin, DNSClass::IN))
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), RecordType::A))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);

    let result = io_loop
        .block_on(client.query(record.name().clone(), record.dns_class(), RecordType::AAAA))
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

fn test_timeout_query(mut client: Client, io_loop: Runtime) {
    let name = Name::from_str("www.example.com").unwrap();

    let err = io_loop
        .block_on(client.query(name.clone(), DNSClass::IN, RecordType::A))
        .unwrap_err();

    println!("got error: {err:?}");
    if let ClientErrorKind::Timeout = err.kind() {
    } else {
        panic!("expected timeout error");
    }

    io_loop
        .block_on(client.query(name, DNSClass::IN, RecordType::AAAA))
        .unwrap_err();

    // test that we don't have any thing funky with registering new timeouts, etc...
    //   it would be cool if we could maintain a different error here, but shutdown is probably ok.
    //
    // match err.kind() {
    //     &ClientErrorKind::Timeout => (),
    //     e @ _ => assert!(false, format!("something else: {}", e)),
    // }
}

#[test]
fn test_timeout_query_nonet() {
    subscribe();
    let io_loop = Runtime::new().expect("failed to create Tokio Runtime");
    let (stream, sender) = NeverReturnsClientStream::new();
    let client = Client::with_timeout(stream, sender, std::time::Duration::from_millis(1), None);
    let (client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    test_timeout_query(client, io_loop);
}

#[test]
fn test_timeout_query_udp() {
    subscribe();
    let io_loop = Runtime::new().unwrap();
    let stream = UdpClientStream::builder(TEST3_V4, TokioRuntimeProvider::new())
        .with_timeout(Some(std::time::Duration::from_millis(1)))
        .build();

    let client = Client::connect(stream);
    let (client, bg) = io_loop.block_on(client).expect("client failed to connect");
    hickory_proto::runtime::spawn_bg(&io_loop, bg);

    test_timeout_query(client, io_loop);
}

#[test]
fn test_timeout_query_tcp() {
    subscribe();
    let io_loop = Runtime::new().unwrap();

    let (stream, sender) = TcpClientStream::new(
        TEST3_V4,
        None,
        Some(std::time::Duration::from_millis(1)),
        TokioRuntimeProvider::new(),
    );
    let client = Client::with_timeout(
        Box::new(stream),
        sender,
        std::time::Duration::from_millis(1),
        None,
    );

    assert!(io_loop.block_on(client).is_err());
}
