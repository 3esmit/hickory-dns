// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::proto::h3::{H3ClientConnect, H3ClientStream};
use crate::proto::runtime::TokioTime;
use crate::proto::xfer::{DnsExchange, DnsExchangeConnect};
use crate::tls::CLIENT_CONFIG;

#[allow(clippy::type_complexity)]
#[allow(unused)]
pub(crate) fn new_h3_stream(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    http_endpoint: String,
    client_config: Option<Arc<rustls::ClientConfig>>,
) -> DnsExchangeConnect<H3ClientConnect, H3ClientStream, TokioTime> {
    let client_config = if let Some(client_config) = client_config {
        client_config
    } else {
        match CLIENT_CONFIG.clone() {
            Ok(client_config) => client_config,
            Err(error) => return DnsExchange::error(error),
        }
    };

    let mut h3_builder = H3ClientStream::builder();

    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    let crypto_config = (*client_config).clone();

    h3_builder.crypto_config(crypto_config);
    if let Some(bind_addr) = bind_addr {
        h3_builder.bind_addr(bind_addr);
    }
    DnsExchange::connect(h3_builder.build(socket_addr, dns_name, http_endpoint))
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_h3_stream_with_future(
    socket: Arc<dyn quinn::AsyncUdpSocket>,
    socket_addr: SocketAddr,
    dns_name: String,
    http_endpoint: String,
    client_config: Option<Arc<rustls::ClientConfig>>,
) -> DnsExchangeConnect<H3ClientConnect, H3ClientStream, TokioTime> {
    let client_config = if let Some(client_config) = client_config {
        client_config
    } else {
        match CLIENT_CONFIG.clone() {
            Ok(client_config) => client_config,
            Err(error) => return DnsExchange::error(error),
        }
    };

    let mut h3_builder = H3ClientStream::builder();

    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    let crypto_config = (*client_config).clone();

    h3_builder.crypto_config(crypto_config);
    DnsExchange::connect(h3_builder.build_with_future(socket, socket_addr, dns_name, http_endpoint))
}

#[cfg(test)]
mod tests {
    use crate::encrypted_tests::{h3_rejects_identity, h3_round_trip};

    #[tokio::test]
    async fn test_local_h3_dns_name_and_ip() {
        for name in ["ns.example.test", "127.0.0.1"] {
            h3_round_trip(name).await;
        }
    }

    #[tokio::test]
    async fn test_local_h3_rejects_wrong_name() {
        h3_rejects_identity(true).await;
    }

    #[tokio::test]
    async fn test_local_h3_rejects_untrusted_root() {
        h3_rejects_identity(false).await;
    }
}
