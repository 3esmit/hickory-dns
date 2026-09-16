// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "dns-over-rustls")]

use std::net::*;
use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::server_harness::{fixture::TlsConfig, query_a_with_background};
use hickory_client::client::Client;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::rustls::tls_client_connect;
use hickory_proto::xfer::Protocol;

#[test]
fn test_example_tls_toml_startup() {
    let fixture = TlsConfig::new("dns_over_tls_rustls_and_openssl.toml");
    fixture.run(|socket_ports| {
        let config = Arc::new(fixture.client_config());
        let tls_port = socket_ports.get_v4(Protocol::Tls);

        let mut io_loop = Runtime::new().unwrap();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tls_port.expect("no tls_port")));

        let provider = TokioRuntimeProvider::new();
        let (stream, sender) = tls_client_connect(
            addr,
            "ns.example.com".to_string(),
            config.clone(),
            provider.clone(),
        );
        let client = Client::new(stream, sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        query_a_with_background(&mut io_loop, &mut client, bg, true);

        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tls_port.expect("no tls_port")));
        let (stream, sender) =
            tls_client_connect(addr, "ns.example.com".to_string(), config, provider);
        let client = Client::new(stream, sender, None);

        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        // A second independently established connection should also work.
        query_a_with_background(&mut io_loop, &mut client, bg, true);
    })
}
