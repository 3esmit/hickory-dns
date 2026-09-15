// Exercise the README lookup flow with deterministic local IPv4 and IPv6 answers.
#[cfg(feature = "tokio-runtime")]
#[tokio::test]
async fn readme_example() {
    use std::net::*;

    use crate::config::*;
    use crate::name_server::TokioConnectionProvider;
    use crate::Resolver;

    use crate::local_dns::LocalDns;
    use crate::proto::rr::{
        rdata::{A, AAAA},
        RData,
    };

    for (data, strategy, expected) in [
        (
            RData::A(A::new(93, 184, 215, 14)),
            LookupIpStrategy::Ipv4Only,
            IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)),
        ),
        (
            RData::AAAA(AAAA::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            )),
            LookupIpStrategy::Ipv6Only,
            IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
            )),
        ),
    ] {
        let server = LocalDns::with_answer(data);
        let resolver = Resolver::new(
            ResolverConfig::from_parts(None, vec![], server.name_servers()),
            ResolverOpts {
                ip_strategy: strategy,
                use_hosts_file: ResolveHosts::Never,
                attempts: 0,
                timeout: std::time::Duration::from_secs(2),
                ..ResolverOpts::default()
            },
            TokioConnectionProvider::default(),
        );

        // Lookup the IP addresses associated with a name.
        let response = resolver.lookup_ip("www.example.com.").await.unwrap();

        // There can be many addresses associated with the name,
        //  this can return IPv4 and/or IPv6 addresses
        let address = response.iter().next().expect("no addresses returned!");
        assert_eq!(address, expected);
        assert_eq!(response.iter().count(), 1);
        drop(resolver);
        server.assert_queries(&["www.example.com."]);
    }
}

// Keep this in sync with the example in the README.
#[cfg(all(feature = "tokio-runtime", feature = "dns-over-tls"))]
#[test]
fn readme_tls() {
    use crate::config::*;
    use crate::name_server::TokioConnectionProvider;
    use crate::Resolver;

    // Construct a new Resolver with default configuration options
    let resolver = Resolver::new(
        ResolverConfig::cloudflare_tls(),
        ResolverOpts::default(),
        TokioConnectionProvider::default(),
    );

    let _ = resolver;
}
