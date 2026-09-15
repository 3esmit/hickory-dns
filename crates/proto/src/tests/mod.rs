//! Tests for TCP and UDP stream and client

#![allow(clippy::print_stdout)] // this is a test module

mod tcp;
mod udp;

#[cfg(all(test, any(feature = "dns-over-https-rustls", feature = "dns-over-h3")))]
mod doh;

#[cfg(all(
    test,
    any(feature = "dns-over-rustls", feature = "dns-over-native-tls")
))]
pub(crate) mod tls;

pub use self::tcp::tcp_client_stream_test;
pub use self::tcp::tcp_stream_test;
pub use self::udp::next_random_socket_test;
pub use self::udp::udp_client_stream_test;
pub use self::udp::udp_stream_test;
