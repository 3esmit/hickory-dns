// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "dns-over-quic")]

use std::net::*;
use tokio::runtime::Runtime;

use crate::server_harness::{fixture::TlsConfig, query_a_with_background};
use hickory_client::client::Client;
use hickory_proto::quic::QuicClientStream;
use hickory_proto::xfer::Protocol;
use test_support::subscribe;

#[test]
fn test_example_quic_toml_startup() {
    subscribe();

    let fixture = TlsConfig::new("dns_over_quic.toml");
    fixture.run(|socket_ports| {
        let client_config = fixture.client_config();
        let quic_port = socket_ports.get_v4(Protocol::Quic);

        let mut io_loop = Runtime::new().unwrap();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, quic_port.expect("no quic_port")));

        let mut quic_builder = QuicClientStream::builder();
        quic_builder.crypto_config(client_config);

        let mp = quic_builder.build(addr, "ns.example.com".to_string());
        let client = Client::connect(mp);

        // ipv4 should succeed
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        query_a_with_background(&mut io_loop, &mut client, bg, true);
    })
}
