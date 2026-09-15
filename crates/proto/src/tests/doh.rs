//! Local authenticated DNS-over-HTTPS round trips, independent of public DNS data.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ClientConfig,
};
use tokio::sync::oneshot;

use crate::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        Name, RData, Record, RecordType,
    },
    tests::tls::TestIdentity,
    xfer::{DnsRequestSender, FirstAnswer},
};

const QUERY_COUNT: usize = 6;
const PATH: &str = "/dns-query";

fn query(index: usize) -> Query {
    Query::query(
        Name::from_ascii("www.example.test.").unwrap(),
        if (1..4).contains(&index) {
            RecordType::AAAA
        } else {
            RecordType::A
        },
    )
}

fn answer(index: usize) -> Record {
    Record::from_rdata(
        query(index).name().clone(),
        60,
        if index == 0 {
            RData::A(A::new(192, 0, 2, 1))
        } else {
            RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        },
    )
}

fn code(index: usize) -> ResponseCode {
    match index {
        4 => ResponseCode::NXDomain,
        5 => ResponseCode::ServFail,
        _ => ResponseCode::NoError,
    }
}

fn reply(bytes: &[u8], index: usize) -> Bytes {
    let request = Message::from_vec(bytes).expect("DNS request");
    assert_eq!(request.message_type(), MessageType::Query);
    assert_eq!(request.queries(), &[query(index)]);
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_response_code(code(index))
        .add_query(query(index));
    if index < 4 {
        response.add_answer(answer(index));
    }
    Bytes::from(response.to_vec().expect("DNS response"))
}

async fn check_queries(client: &mut impl DnsRequestSender) {
    for index in 0..QUERY_COUNT {
        let mut request = Message::new();
        request.add_query(query(index));
        let response = client
            .send_message(request.into())
            .first_answer()
            .await
            .expect("DNS response");
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.queries(), &[query(index)]);
        assert_eq!(response.response_code(), code(index));
        if index < 4 {
            assert_eq!(response.answers(), &[answer(index)]);
        } else {
            assert!(response.answers().is_empty());
        }
    }
}

fn client_config(identity: &TestIdentity) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(identity.ca.to_der().unwrap()))
        .unwrap();
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[cfg(feature = "dns-over-https-rustls")]
async fn https_round_trip(server_name: &str) {
    use crate::{h2::HttpsClientStreamBuilder, http::Version, runtime::TokioRuntimeProvider};
    use futures_util::{stream::FuturesUnordered, StreamExt};

    let identity = TestIdentity::new(server_name).unwrap();
    let client_config = client_config(&identity);
    let cert = vec![CertificateDer::from(identity.cert.to_der().unwrap())];
    let key = PrivatePkcs8KeyDer::from(identity.key.private_key_to_pkcs8().unwrap()).into();
    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(cert, key)
    .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (done, mut finished) = oneshot::channel();
    let server = async {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(tcp)
            .await
            .unwrap();
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
                    let (request, mut response) = incoming.expect("open connection").unwrap();
                    assert!(accepted < QUERY_COUNT);
                    let index = accepted;
                    accepted += 1;
                    requests.push(async move {
                        let bytes = crate::h2::h2_server::message_from(Some(server_name.into()), PATH.into(), request).await.unwrap();
                        let bytes = reply(&bytes, index);
                        let headers = crate::http::response::new(Version::Http2, bytes.len()).unwrap();
                        response.send_response(headers, false).unwrap().send_data(bytes, true).unwrap();
                    });
                }
            }
        }
        assert_eq!(accepted, QUERY_COUNT);
        assert_eq!(completed, QUERY_COUNT);
    };
    let client = async {
        let builder = HttpsClientStreamBuilder::with_client_config(
            Arc::new(client_config),
            TokioRuntimeProvider::new(),
        );
        let mut client = builder
            .build(address, server_name.to_owned(), PATH.to_owned())
            .await
            .unwrap();
        check_queries(&mut client).await;
        done.send(()).unwrap();
    };
    // Both futures and all request handlers are owned here and dropped on timeout.
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server, client);
    })
    .await
    .expect("local H2 timeout");
}

#[cfg(feature = "dns-over-h3")]
async fn h3_round_trip(server_name: &str) {
    use crate::{
        h3::{h3_server::H3Server, H3ClientStream},
        http::Version,
    };
    use bytes::Buf;

    let identity = TestIdentity::new(server_name).unwrap();
    let client_config = client_config(&identity);
    let cert = vec![CertificateDer::from(identity.cert.to_der().unwrap())];
    let key = PrivatePkcs8KeyDer::from(identity.key.private_key_to_pkcs8().unwrap()).into();
    let mut server = H3Server::new(([127, 0, 0, 1], 0).into(), cert, key)
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let (done, finished) = oneshot::channel();
    let server = async {
        let (mut connection, _) = server.accept().await.unwrap().expect("H3 connection");
        for index in 0..QUERY_COUNT {
            let (request, mut stream) = connection.accept().await.expect("H3 request").unwrap();
            crate::http::request::verify(Version::Http3, Some(server_name), PATH, &request)
                .unwrap();
            let mut bytes = Vec::new();
            while let Some(mut frame) = stream.recv_data().await.unwrap() {
                assert!(bytes.len() + frame.remaining() <= 512);
                bytes.extend_from_slice(&frame.copy_to_bytes(frame.remaining()));
            }
            let bytes = reply(&bytes, index);
            stream
                .send_response(crate::http::response::new(Version::Http3, bytes.len()).unwrap())
                .await
                .unwrap();
            stream.send_data(bytes).await.unwrap();
            stream.finish().await.unwrap();
        }
        // Keep the endpoint alive until the client has observed the final response.
        finished.await.unwrap();
    };
    let client = async {
        let mut builder = H3ClientStream::builder();
        builder.crypto_config(client_config);
        let mut client = builder
            .build(address, server_name.to_owned(), PATH.to_owned())
            .await
            .unwrap();
        check_queries(&mut client).await;
        done.send(()).unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server, client);
    })
    .await
    .expect("local H3 timeout");
}

#[cfg(feature = "dns-over-https-rustls")]
#[tokio::test]
async fn https_dns_name() {
    https_round_trip("ns.example.test").await;
}

#[cfg(feature = "dns-over-https-rustls")]
#[tokio::test]
async fn https_ip_address() {
    https_round_trip("127.0.0.1").await;
}

#[cfg(feature = "dns-over-h3")]
#[tokio::test]
async fn h3_dns_name() {
    h3_round_trip("ns.example.test").await;
}

#[cfg(feature = "dns-over-h3")]
#[tokio::test]
async fn h3_ip_address() {
    h3_round_trip("127.0.0.1").await;
}
