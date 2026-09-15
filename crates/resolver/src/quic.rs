// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use rustls::ClientConfig as CryptoConfig;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::proto::quic::{QuicClientConnect, QuicClientStream};
use crate::proto::runtime::TokioTime;
use crate::proto::xfer::{DnsExchange, DnsExchangeConnect};
use crate::tls::CLIENT_CONFIG;

#[allow(clippy::type_complexity)]
#[allow(unused)]
pub(crate) fn new_quic_stream(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Option<Arc<rustls::ClientConfig>>,
) -> DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime> {
    let client_config = if let Some(client_config) = client_config {
        client_config
    } else {
        match CLIENT_CONFIG.clone() {
            Ok(client_config) => client_config,
            Err(error) => return DnsExchange::error(error),
        }
    };

    let mut quic_builder = QuicClientStream::builder();

    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    let crypto_config: CryptoConfig = (*client_config).clone();

    quic_builder.crypto_config(crypto_config);
    if let Some(bind_addr) = bind_addr {
        quic_builder.bind_addr(bind_addr);
    }
    DnsExchange::connect(quic_builder.build(socket_addr, dns_name))
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_quic_stream_with_future(
    socket: Arc<dyn quinn::AsyncUdpSocket>,
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: Option<Arc<rustls::ClientConfig>>,
) -> DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime> {
    let client_config = if let Some(client_config) = client_config {
        client_config
    } else {
        match CLIENT_CONFIG.clone() {
            Ok(client_config) => client_config,
            Err(error) => return DnsExchange::error(error),
        }
    };

    let mut quic_builder = QuicClientStream::builder();

    // TODO: normalize the crypto config settings, can we just use common ALPN settings?
    let crypto_config: CryptoConfig = (*client_config).clone();

    quic_builder.crypto_config(crypto_config);
    DnsExchange::connect(quic_builder.build_with_future(socket, socket_addr, dns_name))
}

#[cfg(test)]
mod tests {
    use crate::encrypted_tests::{quic_rejects_identity, quic_round_trip};

    #[tokio::test]
    async fn test_local_quic_dns_name_and_ip() {
        for name in ["ns.example.test", "127.0.0.1"] {
            quic_round_trip(name).await;
        }
    }

    #[tokio::test]
    async fn test_local_quic_rejects_wrong_name() {
        quic_rejects_identity(true).await;
    }

    #[tokio::test]
    async fn test_local_quic_rejects_untrusted_root() {
        quic_rejects_identity(false).await;
    }
}
