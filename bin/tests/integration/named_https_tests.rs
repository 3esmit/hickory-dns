// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "dns-over-https-rustls")]

use std::net::*;
use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::server_harness::{fixture::TlsConfig, query_a_with_background};
use hickory_client::client::Client;
use hickory_proto::h2::HttpsClientStreamBuilder;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::xfer::Protocol;
use test_support::subscribe;

#[test]
fn test_example_https_toml_startup() {
    subscribe();

    const ALPN_H2: &[u8] = b"h2";

    let fixture = TlsConfig::new("dns_over_https.toml");
    fixture.run(|socket_ports| {
        let mut client_config = fixture.client_config();
        client_config.alpn_protocols.push(ALPN_H2.to_vec());
        let client_config = Arc::new(client_config);
        let https_port = socket_ports.get_v4(Protocol::Https);

        let mut io_loop = Runtime::new().unwrap();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port.expect("no https_port")));

        let provider = TokioRuntimeProvider::new();
        let https_builder = HttpsClientStreamBuilder::with_client_config(client_config, provider);
        let mp = https_builder.build(addr, "ns.example.com".to_string(), "/dns-query".to_string());
        let client = Client::connect(mp);

        // ipv4 should succeed
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        query_a_with_background(&mut io_loop, &mut client, bg, true);
    })
}
