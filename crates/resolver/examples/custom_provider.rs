#![recursion_limit = "128"]

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
use {
    hickory_resolver::{
        config::{ResolverConfig, ResolverOpts},
        name_server::{ConnectionProvider, GenericConnector},
        proto::runtime::{iocompat::AsyncIoTokioAsStd, RuntimeProvider, TokioHandle, TokioTime},
        Resolver,
    },
    std::future::Future,
    std::io,
    std::net::SocketAddr,
    std::pin::Pin,
    std::time::Duration,
    tokio::net::{TcpSocket, TcpStream, UdpSocket},
    tokio::time::timeout,
};

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
#[derive(Clone, Default)]
struct PrintProvider {
    handle: TokioHandle,
}

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
impl RuntimeProvider for PrintProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        Box::pin(async move {
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;

            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }

            socket.set_nodelay(true)?;
            let future = socket.connect(server_addr);
            let wait_for = wait_for.unwrap_or_else(|| Duration::from_secs(5));
            match timeout(wait_for, future).await {
                Ok(Ok(socket)) => Ok(AsyncIoTokioAsStd(socket)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        // The server_addr parameter is used only when you need to establish a tunnel or something similar.
        // For example, you try to use a http proxy and encapsulate UDP packets inside a TCP stream.
        println!(
            "Create udp local_addr: {}, server_addr: {}",
            local_addr, server_addr
        );
        Box::pin(UdpSocket::bind(local_addr))
    }
}

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
async fn lookup<R: ConnectionProvider>(
    resolver: &Resolver<R>,
) -> hickory_resolver::lookup_ip::LookupIp {
    let response = resolver.lookup_ip("www.example.com.").await.unwrap();

    // There can be many addresses associated with the name,
    //  this can return IPv4 and/or IPv6 addresses
    assert!(response.iter().next().is_some(), "no addresses returned!");
    response
}

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
#[tokio::main]
async fn main() {
    let resolver = Resolver::new(
        ResolverConfig::google(),
        ResolverOpts::default(),
        GenericConnector::new(PrintProvider::default()),
    );
    for address in lookup(&resolver).await.iter() {
        println!("{address}");
    }

    #[cfg(feature = "dns-over-https-rustls")]
    {
        let resolver2 = Resolver::new(
            ResolverConfig::cloudflare_https(),
            ResolverOpts::default(),
            GenericConnector::new(PrintProvider::default()),
        );
        for address in lookup(&resolver2).await.iter() {
            println!("{address}");
        }
    }

    println!("Hello, world!");
}

#[cfg(not(any(feature = "webpki-roots", feature = "native-certs")))]
fn main() {
    println!("either `webpki-roots` or `native-certs` feature must be enabled")
}

#[test]
#[cfg(not(any(feature = "webpki-roots", feature = "native-certs")))]
fn test_custom_provider() {
    main()
}

#[cfg(all(test, any(feature = "webpki-roots", feature = "native-certs")))]
use hickory_resolver::{config, proto};
#[cfg(all(test, any(feature = "webpki-roots", feature = "native-certs")))]
#[path = "../src/local_dns.rs"]
mod local_dns;
#[cfg(all(test, any(feature = "webpki-roots", feature = "native-certs")))]
#[path = "custom_provider/tests.rs"]
mod tests;
