// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "dns-over-openssl")]
#![cfg(not(feature = "dns-over-rustls"))]
// TODO: enable this test for rustls as well using below config
// #![cfg(feature = "dns-over-tls")]

use std::net::*;

use native_tls::Certificate;
use tokio::runtime::Runtime;

use hickory_client::client::*;
use hickory_proto::native_tls::TlsClientStreamBuilder;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::xfer::Protocol;

use crate::server_harness::{fixture::TlsConfig, query_a_with_background};

#[test]
fn test_example_tls_toml_startup() {
    test_startup("dns_over_tls.toml")
}

#[test]
fn test_example_tls_rustls_and_openssl_toml_startup() {
    test_startup("dns_over_tls_rustls_and_openssl.toml")
}

fn test_startup(toml: &'static str) {
    let fixture = TlsConfig::new(toml);
    fixture.run(|socket_ports| {
        let cert_der = &fixture.root_der;
        let tls_port = socket_ports.get_v4(Protocol::Tls);

        let provider = TokioRuntimeProvider::new();
        let mut io_loop = Runtime::new().unwrap();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tls_port.expect("no tls_port")));
        let mut tls_conn_builder = TlsClientStreamBuilder::new(provider.clone());
        let cert = to_trust_anchor(cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) = tls_conn_builder.build(addr, "ns.example.com".to_string());
        let client = Client::new(stream, sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        query_a_with_background(&mut io_loop, &mut client, bg, true);

        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tls_port.expect("no tls_port")));
        let mut tls_conn_builder = TlsClientStreamBuilder::new(provider);
        let cert = to_trust_anchor(cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) = tls_conn_builder.build(addr, "ns.example.com".to_string());
        let client = Client::new(stream, sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        // A second connection should also work with this certificate format.
        query_a_with_background(&mut io_loop, &mut client, bg, true);
    })
}

fn to_trust_anchor(cert_der: &[u8]) -> Certificate {
    Certificate::from_der(cert_der).unwrap()
}
