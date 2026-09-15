#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use std::future::Future;
use std::net::*;
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use std::pin::Pin;
#[cfg(feature = "dnssec")]
use std::str::FromStr;
#[cfg(feature = "dnssec")]
use std::sync::Arc;
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use std::sync::Mutex as StdMutex;

use futures::TryStreamExt;
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use time::Duration;

#[cfg(feature = "dnssec")]
use hickory_client::client::DnssecClient;
use hickory_client::client::{Client, ClientHandle};
use hickory_client::ClientErrorKind;
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_integration::example_authority::create_example;
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_integration::TestClientStream;
use hickory_integration::{GOOGLE_V4, TEST3_V4};
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_proto::dnssec::rdata::{DNSSECRData, KEY};
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_proto::dnssec::{openssl::RsaSigningKey, Algorithm, PublicKey, SigSigner, SigningKey};
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_proto::op::MessageFinalizer;
#[cfg(feature = "dnssec")]
use hickory_proto::op::ResponseCode;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_proto::rr::Record;
use hickory_proto::rr::{rdata::A, DNSClass, Name, RData, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_proto::xfer::DnsMultiplexerConnect;
use hickory_proto::xfer::{DnsHandle, DnsMultiplexer};
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_proto::ProtoError;
use hickory_proto::ProtoErrorKind;
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
use hickory_server::authority::{Authority, Catalog};
#[cfg(feature = "dnssec")]
use test_support::subscribe;

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
pub struct TestClientConnection {
    catalog: Arc<StdMutex<Catalog>>,
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
impl TestClientConnection {
    pub fn new(catalog: Catalog) -> TestClientConnection {
        TestClientConnection {
            catalog: Arc::new(StdMutex::new(catalog)),
        }
    }

    #[allow(clippy::type_complexity)]
    fn to_multiplexer(
        &self,
        signer: Option<Arc<dyn MessageFinalizer>>,
    ) -> DnsMultiplexerConnect<
        Pin<Box<dyn Future<Output = Result<TestClientStream, ProtoError>> + Send>>,
        TestClientStream,
    > {
        let (client_stream, handle) = TestClientStream::new(self.catalog.clone());
        DnsMultiplexer::new(Box::pin(client_stream), handle, signer)
    }
}

async fn udp_client(addr: SocketAddr) -> Client {
    let conn = UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
    let (client, driver) = Client::connect(conn).await.expect("failed to connect");
    tokio::spawn(driver);
    client
}

#[cfg(feature = "dnssec")]
async fn udp_dnssec_client(addr: SocketAddr) -> DnssecClient {
    let conn = UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
    let (client, driver) = DnssecClient::connect(conn)
        .await
        .expect("failed to connect");
    tokio::spawn(driver);
    client
}

async fn tcp_client(addr: SocketAddr) -> Client {
    let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::default());
    let multiplexer = DnsMultiplexer::new(stream, sender, None);
    let (client, driver) = Client::connect(multiplexer)
        .await
        .expect("failed to connect");
    tokio::spawn(driver);
    client
}

#[cfg(feature = "dnssec")]
async fn tcp_dnssec_client(addr: SocketAddr) -> DnssecClient {
    let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::default());
    let multiplexer = DnsMultiplexer::new(stream, sender, None);
    let (client, driver) = DnssecClient::connect(multiplexer)
        .await
        .expect("failed to connect");
    tokio::spawn(driver);
    client
}

#[tokio::test]
#[ignore]
#[allow(deprecated)]
async fn test_query_udp() {
    let client = udp_client(GOOGLE_V4).await;
    test_query(client).await;
}

#[tokio::test]
#[allow(deprecated)]
async fn test_query_udp_edns() {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let server = async {
        let mut bytes = [0; 4096];
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let response = super::client_future_tests::local_query_response(&bytes[..length], true);
        assert_eq!(
            socket.send_to(&response, peer).await.unwrap(),
            response.len()
        );
    };
    let client = async {
        let stream = UdpClientStream::builder(address, TokioRuntimeProvider::default()).build();
        let (client, background) = Client::connect(stream).await.unwrap();
        tokio::select! {
            _ = test_query_edns(client) => {}
            result = background => panic!("EDNS driver ended before response: {result:?}"),
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(server, client);
    })
    .await
    .expect("local EDNS timeout");
}

#[tokio::test]
#[ignore]
#[allow(deprecated)]
async fn test_query_tcp() {
    let client = tcp_client(GOOGLE_V4).await;
    test_query(client).await;
}

#[allow(deprecated)]
async fn test_query(mut client: Client) {
    let name = Name::from_ascii("WWW.example.com").unwrap();

    let response = client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .await
        .expect("query failed");

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

    if let RData::A(address) = *record.data() {
        assert_eq!(address, A::new(93, 184, 215, 14))
    } else {
        panic!();
    }
}

async fn test_query_edns(client: Client) {
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

    let response = client
        .send(msg)
        .try_collect::<Vec<_>>()
        .await
        .expect("Query failed")
        .remove(0);

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
}

#[tokio::test]
#[ignore] // this getting finnicky responses with UDP
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
async fn test_secure_query_example_udp() {
    subscribe();
    let client = udp_dnssec_client(GOOGLE_V4).await;
    test_secure_query_example(client).await;
}

#[tokio::test]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
async fn test_secure_query_example_tcp() {
    subscribe();
    use super::local_signed_dns::{drive, SignedDns};
    use hickory_server::dnssec::NxProofKind;

    SignedDns::new(NxProofKind::Nsec)
        .await
        .run(|address, anchor| async move {
            let (stream, sender) =
                TcpClientStream::new(address, None, None, TokioRuntimeProvider::default());
            let multiplexer = DnsMultiplexer::new(stream, sender, None);
            let (client, background) = DnssecClient::builder(multiplexer)
                .trust_anchor(anchor)
                .build()
                .await
                .unwrap();
            drive(background, test_secure_query_example(client)).await;
        })
        .await;
}

#[cfg(feature = "dnssec")]
async fn test_secure_query_example(mut client: DnssecClient) {
    subscribe();

    let name = Name::from_str("www.example.com").unwrap();

    let response = client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .await
        .expect("Query failed");

    println!("response records: {response:?}");
    assert!(
        response
            .extensions()
            .as_ref()
            .expect("edns not here")
            .flags()
            .dnssec_ok
    );

    let record = &response.answers()[0];
    assert_eq!(record.proof(), hickory_proto::dnssec::Proof::Secure);
    assert_eq!(record.name(), &name);
    assert_eq!(record.record_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);

    if let RData::A(address) = *record.data() {
        assert_eq!(address, A::new(93, 184, 215, 14))
    } else {
        panic!();
    }
}

async fn test_timeout_query(mut client: Client) {
    let name = Name::from_ascii("WWW.example.com").unwrap();

    let response = client.query(name, DNSClass::IN, RecordType::A).await;
    assert!(response.is_err());

    let err = response.unwrap_err();

    if let ClientErrorKind::Timeout = err.kind() {
    } else {
        panic!("expected timeout error")
    }
}

#[tokio::test]
async fn test_timeout_query_udp() {
    let client = udp_client(TEST3_V4).await;
    test_timeout_query(client).await;
}

#[tokio::test]
async fn test_timeout_query_tcp() {
    let (stream, sender) = TcpClientStream::new(
        TEST3_V4,
        None,
        Some(std::time::Duration::from_millis(1)),
        TokioRuntimeProvider::default(),
    );

    let multiplexer = DnsMultiplexer::new(stream, sender, None);
    match Client::connect(multiplexer).await {
        Err(e) if matches!(e.kind(), ProtoErrorKind::Timeout) => {}
        _ => panic!("expected timeout"),
    }
}

// // TODO: this test is flaky
// #[test]
// #[ignore]
// #[allow(deprecated)]
// fn test_dnssec_rollernet_td_udp() {
//     let c = SyncDnssecClient::new(UdpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap())
//         .build();
//     c.secure_query(
//         &Name::parse("rollernet.us.", None).unwrap(),
//         DNSClass::IN,
//         RecordType::DS),
//     ).unwrap();
// }

// // TODO: this test is flaky
// #[test]
// #[ignore]
// #[allow(deprecated)]
// fn test_dnssec_rollernet_td_tcp() {
//     let c = SyncDnssecClient::new(TcpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap())
//         .build();
//     c.secure_query(
//         &Name::parse("rollernet.us.", None).unwrap(),
//         DNSClass::IN,
//         RecordType::DS),
//     ).unwrap();
// }

// // TODO: this test is flaky
// #[test]
// #[ignore]
// #[allow(deprecated)]
// fn test_dnssec_rollernet_td_tcp_mixed_case() {
//     let c = SyncDnssecClient::new(TcpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap())
//         .build();
//     c.secure_query(
//         &Name::parse("RollErnet.Us.", None).unwrap(),
//         DNSClass::IN,
//         RecordType::DS),
//     ).unwrap();
// }

#[tokio::test]
#[ignore]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
async fn test_nsec_query_example_udp() {
    let client = udp_dnssec_client(GOOGLE_V4).await;
    test_nsec_query_example(client).await;
}

#[tokio::test]
#[ignore]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
async fn test_nsec_query_example_tcp() {
    let client = tcp_dnssec_client(GOOGLE_V4).await;
    test_nsec_query_example(client).await;
}

#[cfg(feature = "dnssec")]
async fn test_nsec_query_example(mut client: DnssecClient) {
    let name = Name::from_str("none.example.com").unwrap();

    let response = client
        .query(name, DNSClass::IN, RecordType::A)
        .await
        .expect("Query failed");

    assert_eq!(response.response_code(), ResponseCode::NXDomain);
}

#[tokio::test]
#[ignore]
#[cfg(feature = "dnssec")]
async fn test_nsec_query_type() {
    let mut client = tcp_dnssec_client(GOOGLE_V4).await;

    let name = Name::from_str("www.example.com").unwrap();
    let response = client
        .query(name, DNSClass::IN, RecordType::NS)
        .await
        .expect("Query failed");

    // TODO: it would be nice to verify that the NSEC records were validated...
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());
}

// NSEC3 tests
#[tokio::test]
#[cfg(feature = "dnssec")]
async fn test_nsec3_nxdomain() {
    use super::local_signed_dns::{drive, SignedDns};
    use hickory_proto::dnssec::{Nsec3HashAlgorithm, Proof};
    use hickory_server::dnssec::NxProofKind;

    SignedDns::new(NxProofKind::Nsec3 {
        algorithm: Nsec3HashAlgorithm::default(),
        salt: Arc::from([1, 2, 3]),
        iterations: 1,
    })
    .await
    .run(|address, anchor| async move {
        let (stream, sender) =
            TcpClientStream::new(address, None, None, TokioRuntimeProvider::default());
        let multiplexer = DnsMultiplexer::new(stream, sender, None);
        let (mut client, background) = DnssecClient::builder(multiplexer)
            .trust_anchor(anchor)
            .build()
            .await
            .unwrap();
        drive(background, async {
            let mut saw_multiple_proofs = false;
            for name in [
                "a.b.c.example.com.",
                "nonexistent.example.com.",
                "a.www.example.com.",
            ] {
                let name = Name::from_ascii(name).unwrap();
                let response = client
                    .query(name.clone(), DNSClass::IN, RecordType::NS)
                    .await
                    .expect("Query failed");
                assert_eq!(response.response_code(), ResponseCode::NXDomain);
                assert!(response.answers().is_empty());
                assert_eq!(response.queries(), &[Query::query(name, RecordType::NS)]);
                assert!(response
                    .name_servers()
                    .iter()
                    .any(|record| record.record_type() == RecordType::NSEC3));
                saw_multiple_proofs |= response
                    .name_servers()
                    .iter()
                    .filter(|record| record.record_type() == RecordType::NSEC3)
                    .count()
                    > 1;
                for (index, record) in response.name_servers().iter().enumerate() {
                    assert!(
                        !response.name_servers()[..index].contains(record),
                        "duplicate proof record: {record:?}"
                    );
                    assert_eq!(record.proof(), Proof::Secure, "{record:?}");
                }
            }
            assert!(
                saw_multiple_proofs,
                "distinct proof records must also be preserved"
            );
        })
        .await;
    })
    .await;
}

#[tokio::test]
#[cfg(feature = "dnssec")]
async fn test_nsec3_no_data() {
    let name = Name::from_labels(vec!["www", "example", "com"]).unwrap();

    let mut client = tcp_dnssec_client(GOOGLE_V4).await;
    let response = client
        .query(name, DNSClass::IN, RecordType::PTR)
        .await
        .expect("Query failed");

    // the name "www.example.com" exists but there's no PTR record on it
    assert_eq!(response.response_code(), ResponseCode::NoError);
}

#[tokio::test]
#[ignore]
#[cfg(feature = "dnssec")]
async fn test_nsec3_query_name_is_soa_name() {
    let name = Name::from_labels("valid.extended-dns-errors.com".split(".")).unwrap();

    let mut client = tcp_dnssec_client(GOOGLE_V4).await;
    let response = client
        .query(name, DNSClass::IN, RecordType::PTR)
        .await
        .expect("Query failed");

    // the name "valid.extended-dns-errors.com" exists but there's no PTR record on it
    assert_eq!(response.response_code(), ResponseCode::NoError);
}

// TODO: disabled until I decide what to do with NSEC3 see issue #10
//
// TODO these NSEC3 tests don't work, it seems that the zone is not signed properly.
// #[test]
// #[ignore]
// fn test_nsec3_sdsmt() {
//   let addr: SocketAddr = ("75.75.75.75",53).to_socket_addrs().unwrap().next().unwrap();
//   let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
//   let name = Name::from_labels(vec!["none", "sdsmt", "edu"]);
//   let client = Client::new(conn);
//
//   let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
//   assert!(response.is_ok(), "query failed: {}", response.unwrap_err());
//
//   let response = response.unwrap();
//   assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
// }

// TODO: disabled until I decide what to do with NSEC3 see issue #10
//
// #[test]
// #[ignore]
// fn test_nsec3_sdsmt_type() {
//   let addr: SocketAddr = ("75.75.75.75",53).to_socket_addrs().unwrap().next().unwrap();
//   let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
//   let name = Name::from_labels(vec!["www", "sdsmt", "edu"]);
//   let client = Client::new(conn);
//
//   let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
//   assert!(response.is_ok(), "query failed: {}", response.unwrap_err());
//
//   let response = response.unwrap();
//   assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
// }

#[allow(deprecated)]
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
async fn create_sig0_ready_client(mut catalog: Catalog) -> (Client, Name) {
    use hickory_server::store::sqlite::SqliteAuthority;

    let authority = create_example();
    let mut authority = SqliteAuthority::new(authority, true, false);
    authority.set_allow_update(true);
    let origin = authority.origin().clone();

    let key = RsaSigningKey::generate(Algorithm::RSASHA256).unwrap();
    let pub_key = key.to_public_key().unwrap();

    let signer = SigSigner::new(
        Algorithm::RSASHA256,
        Box::new(key),
        Name::from_str("trusted.example.com").unwrap(),
        // can be Duration::MAX after min Rust version 1.53
        std::time::Duration::new(u64::MAX, 1_000_000_000 - 1),
        true,
        true,
    );

    // insert the KEY for the trusted.example.com
    let auth_key = Record::from_rdata(
        Name::from_str("trusted.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::DNSSEC(DNSSECRData::KEY(KEY::new(
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            signer.algorithm(),
            pub_key.public_bytes().to_vec(),
        ))),
    );
    authority.upsert_mut(auth_key, 0);

    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);
    let multiplexer = TestClientConnection::new(catalog).to_multiplexer(Some(Arc::new(signer)));
    let (client, driver) = Client::connect(multiplexer)
        .await
        .expect("failed to connect");
    tokio::spawn(driver);

    (client, origin.into())
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_create() {
    let catalog = Catalog::new();
    let (mut client, origin) = create_sig0_ready_client(catalog).await;

    // create a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    record.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = client.create(record, origin).await.expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_append() {
    let catalog = Catalog::new();
    let (mut client, origin) = create_sig0_ready_client(catalog).await;

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = client
        .append(record.clone(), origin.clone(), true)
        .await
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = client
        .append(record.clone(), origin.clone(), false)
        .await
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    record.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = client
        .append(record.clone(), origin.clone(), true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = *rr.data() {
            ip == A::new(100, 10, 100, 10)
        } else {
            false
        }));
    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = rr.data() {
            *ip == A::new(101, 11, 101, 11)
        } else {
            false
        }));

    // show that appending the same thing again is ok, but doesn't add any records
    let result = client
        .append(record.clone(), origin, true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_compare_and_swap() {
    let catalog = Catalog::new();
    let (mut client, origin) = create_sig0_ready_client(catalog).await;

    // create a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = client
        .compare_and_swap(current.clone(), new.clone(), origin.clone())
        .await
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(new.name().clone(), new.dns_class(), new.record_type())
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = rr.data() {
            *ip == A::new(101, 11, 101, 11)
        } else {
            false
        }));

    // check the it fails if tried again.
    new.set_data(RData::A(A::new(102, 12, 102, 12)));

    let result = client
        .compare_and_swap(current, new.clone(), origin)
        .await
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = client
        .query(new.name().clone(), new.dns_class(), new.record_type())
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = rr.data() {
            *ip == A::new(101, 11, 101, 11)
        } else {
            false
        }));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_delete_by_rdata() {
    let catalog = Catalog::new();
    let (mut client, origin) = create_sig0_ready_client(catalog).await;

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = client
        .delete_by_rdata(record.clone(), origin.clone())
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    record.set_data(RData::A(A::new(101, 11, 101, 11)));
    let result = client
        .append(record.clone(), origin.clone(), true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_by_rdata(record.clone(), origin)
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = rr.data() {
            *ip == A::new(100, 10, 100, 10)
        } else {
            false
        }));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_delete_rrset() {
    let catalog = Catalog::new();
    let (mut client, origin) = create_sig0_ready_client(catalog).await;

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = client
        .delete_rrset(record.clone(), origin.clone())
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    record.set_data(RData::A(A::new(101, 11, 101, 11)));
    let result = client
        .append(record.clone(), origin.clone(), true)
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_rrset(record.clone(), origin)
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[tokio::test]
async fn test_delete_all() {
    use hickory_proto::rr::rdata::AAAA;

    let catalog = Catalog::new();
    let (mut client, origin) = create_sig0_ready_client(catalog).await;

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    // first check the must_exist option
    let result = client
        .delete_all(record.name().clone(), origin.clone(), DNSClass::IN)
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    record.set_data(RData::AAAA(AAAA::new(1, 2, 3, 4, 5, 6, 7, 8)));
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_all(record.name().clone(), origin, DNSClass::IN)
        .await
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name().clone(), record.dns_class(), RecordType::A)
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);

    let result = client
        .query(record.name().clone(), record.dns_class(), RecordType::AAAA)
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}
