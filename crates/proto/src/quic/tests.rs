// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::print_stdout)] // this is a test module

use std::{net::SocketAddr, str::FromStr, sync::Arc};

use futures_util::StreamExt;
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ClientConfig, KeyLogFile,
};

use crate::{
    op::{Message, Query},
    quic::QuicClientStreamBuilder,
    rr::{Name, RecordType},
    xfer::DnsRequestSender,
};

use super::quic_server::QuicServer;

async fn server_responder(mut server: QuicServer) {
    while let Some((mut conn, addr)) = server
        .next()
        .await
        .expect("failed to get next quic session")
    {
        println!("received client request {addr}");

        while let Some(stream) = conn.next().await {
            let mut stream = stream.expect("new client stream failed");

            let client_message = stream.receive().await.expect("failed to receive");

            // just response with the same message.
            stream
                .send(client_message.into_message())
                .await
                .expect("failed to send response")
        }
    }
}

#[tokio::test]
async fn test_quic_stream() {
    let dns_name = "ns.example.com";

    let identity = crate::tests::tls::TestIdentity::new(dns_name).expect("test identity");
    let ca = [CertificateDer::from(
        identity.ca.to_der().expect("root DER"),
    )];
    let cert = vec![CertificateDer::from(
        identity.cert.to_der().expect("server DER"),
    )];
    let key =
        PrivatePkcs8KeyDer::from(identity.key.private_key_to_pkcs8().expect("server key")).into();

    // All testing is only done on local addresses, construct the server
    let quic_ns = QuicServer::new(SocketAddr::from(([127, 0, 0, 1], 0)), cert, key)
        .await
        .expect("failed to initialize QuicServer");

    // kick off the server
    let server_addr = quic_ns.local_addr().expect("no address");
    println!("testing quic on: {server_addr}");
    let server_join = tokio::spawn(server_responder(quic_ns));

    // now construct the client
    let mut roots = rustls::RootCertStore::empty();
    let (_, ignored) = roots.add_parsable_certificates(ca.into_iter());
    assert_eq!(ignored, 0);

    let mut client_config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

    client_config.key_log = Arc::new(KeyLogFile::new());

    let mut builder = QuicClientStreamBuilder::default();
    builder.crypto_config(client_config);

    println!("starting quic connect");
    let mut client_stream = builder
        .build(server_addr, dns_name.to_string())
        .await
        .expect("failed to connect");

    println!("connected client to server");

    // create a test message, send and then receive...
    let mut message = Message::default();
    message.add_query(Query::query(
        Name::from_str("www.example.test.").unwrap(),
        RecordType::AAAA,
    ));

    // TODO: we should make the finalizer easier to call so this round-trip serialization isn't necessary.
    let bytes = message.to_vec().unwrap();
    let message = Message::from_vec(&bytes).unwrap();

    let response = client_stream
        .send_message(message.clone().into())
        .next()
        .await
        .expect("no response received")
        .expect("failed to read response");

    assert_eq!(*response, message);

    // and finally kill the server
    server_join.abort();
    let stopped = server_join.await.expect_err("server must stop after abort");
    assert!(
        stopped.is_cancelled(),
        "server failed before cleanup: {stopped}"
    );
}
