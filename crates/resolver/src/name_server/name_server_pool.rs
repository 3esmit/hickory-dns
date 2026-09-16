// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::future::FutureExt;
use futures_util::stream::{once, FuturesUnordered, Stream, StreamExt};
use rand::thread_rng as rng;
use rand::Rng;
use smallvec::SmallVec;
use tracing::debug;

use crate::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts, ServerOrderingStrategy};
use crate::name_server::connection_provider::{ConnectionProvider, GenericConnector};
use crate::name_server::name_server::NameServer;
use crate::proto::runtime::{RuntimeProvider, Time};
use crate::proto::xfer::{DnsHandle, DnsRequest, DnsResponse, FirstAnswer};
use crate::proto::{ProtoError, ProtoErrorKind};

/// A pool of NameServers
///
/// This is not expected to be used directly, see [crate::AsyncResolver].
pub type GenericNameServerPool<P> = NameServerPool<GenericConnector<P>>;

/// Abstract interface for mocking purpose
#[derive(Clone)]
pub struct NameServerPool<P: ConnectionProvider + Send + 'static> {
    // TODO: switch to FuturesMutex (Mutex will have some undesirable locking)
    datagram_conns: Arc<[NameServer<P>]>, /* All NameServers must be the same type */
    stream_conns: Arc<[NameServer<P>]>,   /* All NameServers must be the same type */
    options: ResolverOpts,
    datagram_index: Arc<AtomicUsize>,
    stream_index: Arc<AtomicUsize>,
}

impl<P> NameServerPool<P>
where
    P: ConnectionProvider + 'static,
{
    pub(crate) fn from_config_with_provider(
        config: &ResolverConfig,
        options: ResolverOpts,
        conn_provider: P,
    ) -> Self {
        let datagram_conns = config
            .name_servers()
            .iter()
            .filter(|ns_config| ns_config.protocol.is_datagram())
            .map(|ns_config| {
                #[cfg(feature = "dns-over-rustls")]
                let ns_config = {
                    let mut ns_config = ns_config.clone();
                    ns_config.tls_config = config.client_config().cloned();
                    ns_config
                };
                #[cfg(not(feature = "dns-over-rustls"))]
                let ns_config = { ns_config.clone() };

                NameServer::new(ns_config, options.clone(), conn_provider.clone())
            })
            .collect();

        let stream_conns = config
            .name_servers()
            .iter()
            .filter(|ns_config| ns_config.protocol.is_stream())
            .map(|ns_config| {
                #[cfg(feature = "dns-over-rustls")]
                let ns_config = {
                    let mut ns_config = ns_config.clone();
                    ns_config.tls_config = config.client_config().cloned();
                    ns_config
                };
                #[cfg(not(feature = "dns-over-rustls"))]
                let ns_config = { ns_config.clone() };

                NameServer::new(ns_config, options.clone(), conn_provider.clone())
            })
            .collect();

        Self {
            datagram_conns,
            stream_conns,
            options,
            datagram_index: Arc::from(AtomicUsize::new(0)),
            stream_index: Arc::from(AtomicUsize::new(0)),
        }
    }

    /// Construct a NameServerPool from a set of name server configs
    pub fn from_config(
        name_servers: NameServerConfigGroup,
        options: ResolverOpts,
        conn_provider: P,
    ) -> Self {
        let map_config_to_ns =
            |ns_config| NameServer::new(ns_config, options.clone(), conn_provider.clone());

        let (datagram, stream): (Vec<_>, Vec<_>) = name_servers
            .into_inner()
            .into_iter()
            .partition(|ns| ns.protocol.is_datagram());

        let datagram_conns: Vec<_> = datagram.into_iter().map(map_config_to_ns).collect();
        let stream_conns: Vec<_> = stream.into_iter().map(map_config_to_ns).collect();

        Self {
            datagram_conns: Arc::from(datagram_conns),
            stream_conns: Arc::from(stream_conns),
            options,
            datagram_index: Arc::from(AtomicUsize::new(0)),
            stream_index: Arc::from(AtomicUsize::new(0)),
        }
    }

    #[doc(hidden)]
    pub fn from_nameservers(
        options: ResolverOpts,
        datagram_conns: Vec<NameServer<P>>,
        stream_conns: Vec<NameServer<P>>,
    ) -> Self {
        Self {
            datagram_conns: Arc::from(datagram_conns),
            stream_conns: Arc::from(stream_conns),
            options,
            datagram_index: Arc::from(AtomicUsize::new(0)),
            stream_index: Arc::from(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn from_nameservers_test(
        options: ResolverOpts,
        datagram_conns: Arc<[NameServer<P>]>,
        stream_conns: Arc<[NameServer<P>]>,
    ) -> Self {
        Self {
            datagram_conns,
            stream_conns,
            options,
            datagram_index: Arc::from(AtomicUsize::new(0)),
            stream_index: Arc::from(AtomicUsize::new(0)),
        }
    }

    async fn try_send(
        opts: ResolverOpts,
        conns: Arc<[NameServer<P>]>,
        request: DnsRequest,
        next_index: &Arc<AtomicUsize>,
    ) -> Result<DnsResponse, ProtoError> {
        let mut conns: Vec<NameServer<P>> = conns.to_vec();

        match opts.server_ordering_strategy {
            // select the highest priority connection
            //   reorder the connections based on current view...
            //   this reorders the inner set
            ServerOrderingStrategy::QueryStatistics => conns.sort_unstable(),
            ServerOrderingStrategy::UserProvidedOrder => {}
            ServerOrderingStrategy::RoundRobin => {
                let num_concurrent_reqs = if opts.num_concurrent_reqs > 1 {
                    opts.num_concurrent_reqs
                } else {
                    1
                };
                if num_concurrent_reqs < conns.len() {
                    let index = next_index.fetch_add(num_concurrent_reqs, AtomicOrdering::SeqCst)
                        % conns.len();
                    conns.rotate_left(index);
                }
            }
        }
        let request_loop = request.clone();

        parallel_conn_loop(conns, request_loop, opts).await
    }
}

impl<P> DnsHandle for NameServerPool<P>
where
    P: ConnectionProvider + 'static,
{
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

    fn send<R: Into<DnsRequest>>(&self, request: R) -> Self::Response {
        let opts = self.options.clone();
        let request = request.into();
        let datagram_conns = Arc::clone(&self.datagram_conns);
        let stream_conns = Arc::clone(&self.stream_conns);
        let datagram_index = Arc::clone(&self.datagram_index);
        let stream_index = Arc::clone(&self.stream_index);
        // TODO: remove this clone, return the Message in the error?
        // TODO: remove this clone, return the Message in the error?
        let tcp_message = request.clone();

        // TODO: limited to only when mDNS is enabled, but this should probably always be enforced?
        let mdns = Local::NotMdns(request);

        // local queries are queried through mDNS
        if mdns.is_local() {
            return mdns.take_stream();
        }

        // TODO: should we allow mDNS to be used for standard lookups as well?

        // it wasn't a local query, continue with standard lookup path
        let request = mdns.take_request();
        Box::pin(once(async move {
            debug!("sending request: {:?}", request.queries());

            // First try the UDP connections
            let future = Self::try_send(opts.clone(), datagram_conns, request, &datagram_index);
            let udp_res = match future.await {
                Ok(response) if response.truncated() => {
                    debug!("truncated response received, retrying over TCP");
                    Ok(response)
                }
                Err(e) if (opts.try_tcp_on_error && e.is_io()) || e.is_no_connections() => {
                    debug!("error from UDP, retrying over TCP: {}", e);
                    Err(e)
                }
                result => return result,
            };

            if stream_conns.is_empty() {
                debug!("no TCP connections available");
                return udp_res;
            }

            // Try query over TCP, as response to query over UDP was either truncated or was an
            // error.
            let tcp_res = Self::try_send(opts, stream_conns, tcp_message, &stream_index).await;

            let tcp_err = match tcp_res {
                res @ Ok(..) => return res,
                Err(e) => e,
            };

            // Even if the UDP result was truncated, return that
            let udp_err = match udp_res {
                Ok(response) => return Ok(response),
                Err(e) => e,
            };

            match udp_err.cmp_specificity(&tcp_err) {
                Ordering::Greater => Err(udp_err),
                _ => Err(tcp_err),
            }
        }))
    }
}

// TODO: we should be able to have a self-referential future here with Pin and not require cloned conns
/// An async function that will loop over all the conns with a max parallel request count of ops.num_concurrent_req
async fn parallel_conn_loop<P>(
    mut conns: Vec<NameServer<P>>,
    request: DnsRequest,
    opts: ResolverOpts,
) -> Result<DnsResponse, ProtoError>
where
    P: ConnectionProvider + 'static,
{
    let mut err = ProtoError::from(ProtoErrorKind::NoConnections);

    // If the name server we're trying is giving us backpressure by returning ProtoErrorKind::Busy,
    // we will first try the other name servers (as for other error types). However, if the other
    // servers are also busy, we're going to wait for a little while and then retry each server that
    // returned Busy in the previous round. If the server is still Busy, this continues, while
    // the backoff increases exponentially (by a factor of 2), until it hits 300ms, in which case we
    // give up. The request might still be retried by the caller (likely the DnsRetryHandle).
    //
    // TODO: more principled handling of timeouts. Currently, timeouts appear to be handled mostly
    // close to the connection, which means the top level resolution might take substantially longer
    // to fire than the timeout configured in `ResolverOpts`.
    let mut backoff = Duration::from_millis(20);
    let mut busy = SmallVec::<[NameServer<P>; 2]>::new();

    loop {
        let request_cont = request.clone();

        // construct the parallel requests, 2 is the default
        let mut par_conns = SmallVec::<[NameServer<P>; 2]>::new();
        let count = conns.len().min(opts.num_concurrent_reqs.max(1));

        // Shuffe DNS NameServers to avoid overloads to the first configured ones
        if opts.shuffle_dns_servers {
            for _ in 0..count {
                let idx = rng().gen_range(0..conns.len());

                // UNWRAP: swap_remove has an implicit panicking bounds check. This should
                // never fail because we check that conns is not empty and generate the idx
                // to explicitly be in range.
                par_conns.push(conns.swap_remove(idx));
            }
        } else {
            for conn in conns.drain(..count) {
                par_conns.push(conn);
            }
        }

        if par_conns.is_empty() {
            if !busy.is_empty() && backoff < Duration::from_millis(300) {
                <<P as ConnectionProvider>::RuntimeProvider as RuntimeProvider>::Timer::delay_for(
                    backoff,
                )
                .await;
                conns.extend(busy.drain(..));
                backoff *= 2;
                continue;
            }
            return Err(err);
        }

        let mut requests = par_conns
            .into_iter()
            .map(move |conn| {
                conn.send(request_cont.clone())
                    .first_answer()
                    .map(|result| result.map_err(|e| Box::new((conn, e))))
            })
            .collect::<FuturesUnordered<_>>();

        while let Some(result) = requests.next().await {
            let (conn, e) = match result {
                Ok(sent) => return Ok(sent),
                Err(error) => *error,
            };

            match e.kind() {
                ProtoErrorKind::NoRecordsFound {
                    trusted, soa, ns, ..
                } if *trusted || soa.is_some() || ns.is_some() => {
                    return Err(e);
                }
                _ if e.is_busy() => {
                    busy.push(conn);
                }
                // If our current error is the default err we start with, replace it with the
                // new error under consideration. It was produced trying to make a connection
                // and is more specific than the default.
                _ if matches!(err.kind(), ProtoErrorKind::NoConnections) => {
                    err = e;
                }
                _ if err.cmp_specificity(&e) == Ordering::Less => {
                    err = e;
                }
                _ => {}
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum Local {
    #[allow(dead_code)]
    ResolveStream(Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>),
    NotMdns(DnsRequest),
}

impl Local {
    fn is_local(&self) -> bool {
        matches!(*self, Self::ResolveStream(..))
    }

    /// Takes the stream
    ///
    /// # Panics
    ///
    /// Panics if this is in fact a Local::NotMdns
    fn take_stream(self) -> Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>> {
        match self {
            Self::ResolveStream(future) => future,
            _ => panic!("non Local queries have no future, see take_message()"),
        }
    }

    /// Takes the message
    ///
    /// # Panics
    ///
    /// Panics if this is in fact a Local::ResolveStream
    fn take_request(self) -> DnsRequest {
        match self {
            Self::NotMdns(request) => request,
            _ => panic!("Local queries must be polled, see take_future()"),
        }
    }
}

impl Stream for Local {
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            Self::ResolveStream(ns) => ns.as_mut().poll_next(cx),
            // TODO: making this a panic for now
            Self::NotMdns(..) => panic!("Local queries that are not mDNS should not be polled"), //Local::NotMdns(message) => return Err(ResolveErrorKind::Message("not mDNS")),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
mod tests {
    use std::future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::runtime::Runtime;

    use super::*;
    use crate::config::NameServerConfig;
    use crate::name_server::connection_provider::TokioConnectionProvider;
    use crate::name_server::GenericNameServer;
    use crate::proto::op::Query;
    use crate::proto::rr::{Name, RecordType};
    use crate::proto::runtime::TokioRuntimeProvider;
    use crate::proto::xfer::{DnsHandle, DnsRequestOptions, Protocol};

    #[derive(Clone)]
    struct MockConnectionProvider(crate::lookup_ip::tests::MockDnsHandle);

    impl ConnectionProvider for MockConnectionProvider {
        type Conn = crate::lookup_ip::tests::MockDnsHandle;
        type FutureConn = future::Ready<Result<Self::Conn, ProtoError>>;
        type RuntimeProvider = TokioRuntimeProvider;

        fn new_connection(
            &self,
            _: &NameServerConfig,
            _: &ResolverOpts,
        ) -> Result<Self::FutureConn, std::io::Error> {
            Ok(future::ready(Ok(self.0.clone())))
        }
    }

    fn mock_server(
        messages: Vec<Result<DnsResponse, ProtoError>>,
    ) -> NameServer<MockConnectionProvider> {
        NameServer::new(
            NameServerConfig::new(([127, 0, 0, 1], 53).into(), Protocol::Udp),
            ResolverOpts::default(),
            MockConnectionProvider(crate::lookup_ip::tests::mock(messages)),
        )
    }

    fn mock_request() -> DnsRequest {
        let mut message = crate::proto::op::Message::new();
        message.add_query(Query::query(Name::root(), RecordType::A));
        message.into()
    }

    #[tokio::test(start_paused = true)]
    async fn test_parallel_busy_connection_is_retried() {
        let expected = crate::lookup_ip::tests::v4_message().unwrap();
        // The existing mock consumes responses from the end of the vector.
        let server = mock_server(vec![Ok(expected.clone()), Err(ProtoErrorKind::Busy.into())]);
        let started = tokio::time::Instant::now();
        let response = parallel_conn_loop(vec![server], mock_request(), ResolverOpts::default())
            .await
            .unwrap();
        assert_eq!(response.answers(), expected.answers());
        assert_eq!(started.elapsed(), Duration::from_millis(20));
    }

    #[tokio::test(start_paused = true)]
    async fn test_parallel_failed_connection_preserves_fallback() {
        let expected = crate::lookup_ip::tests::v4_message().unwrap();
        let servers = vec![
            mock_server(vec![Err(ProtoErrorKind::Timeout.into())]),
            mock_server(vec![Ok(expected.clone())]),
        ];
        let options = ResolverOpts {
            num_concurrent_reqs: 1,
            shuffle_dns_servers: false,
            ..ResolverOpts::default()
        };
        let started = tokio::time::Instant::now();
        let response = parallel_conn_loop(servers, mock_request(), options)
            .await
            .unwrap();
        assert_eq!(response.answers(), expected.answers());
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn test_parallel_busy_backoff_remains_bounded() {
        let messages = (0..5).map(|_| Err(ProtoErrorKind::Busy.into())).collect();
        let started = tokio::time::Instant::now();
        let error = parallel_conn_loop(
            vec![mock_server(messages)],
            mock_request(),
            ResolverOpts::default(),
        )
        .await
        .unwrap_err();
        assert!(error.is_no_connections());
        assert_eq!(started.elapsed(), Duration::from_millis(300));
    }

    #[ignore]
    // because of there is a real connection that needs a reasonable timeout
    #[test]
    #[allow(clippy::uninlined_format_args)]
    fn test_failed_then_success_pool() {
        let config1 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 253),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            http_endpoint: None,
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: None,
        };

        let config2 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            http_endpoint: None,
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: None,
        };

        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(config1);
        resolver_config.add_name_server(config2);

        let io_loop = Runtime::new().unwrap();
        let pool = GenericNameServerPool::tokio_from_config(
            &resolver_config,
            ResolverOpts::default(),
            TokioRuntimeProvider::new(),
        );

        let name = Name::parse("www.example.com.", None).unwrap();

        // TODO: it's not clear why there are two failures before the success
        for i in 0..2 {
            assert!(
                io_loop
                    .block_on(
                        pool.lookup(
                            Query::query(name.clone(), RecordType::A),
                            DnsRequestOptions::default()
                        )
                        .first_answer()
                    )
                    .is_err(),
                "iter: {}",
                i
            );
        }

        for i in 0..10 {
            assert!(
                io_loop
                    .block_on(
                        pool.lookup(
                            Query::query(name.clone(), RecordType::A),
                            DnsRequestOptions::default()
                        )
                        .first_answer()
                    )
                    .is_ok(),
                "iter: {}",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_multi_use_conns() {
        use crate::proto::{
            op::{Message, MessageType, ResponseCode},
            rr::{
                rdata::{A, AAAA},
                RData, Record,
            },
        };
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let name = Name::from_ascii("www.example.test.").unwrap();
        let records = [
            Record::from_rdata(name.clone(), 60, RData::A(A::new(192, 0, 2, 1))),
            Record::from_rdata(
                name.clone(),
                60,
                RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ),
        ];
        let (done, finished) = tokio::sync::oneshot::channel();
        let server = async {
            // Accept exactly one connection: both record types must use it.
            let (mut socket, _) = listener.accept().await.unwrap();
            for record in &records {
                let length = usize::from(socket.read_u16().await.unwrap());
                assert!(length <= 4096);
                let mut bytes = vec![0; length];
                socket.read_exact(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes).unwrap();
                let query = Query::query(name.clone(), record.record_type());
                assert_eq!(request.message_type(), MessageType::Query);
                assert_eq!(request.queries(), std::slice::from_ref(&query));
                let mut response = Message::new();
                response
                    .set_id(request.id())
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NoError)
                    .add_query(query)
                    .add_answer(record.clone());
                let bytes = response.to_vec().unwrap();
                socket
                    .write_u16(bytes.len().try_into().unwrap())
                    .await
                    .unwrap();
                socket.write_all(&bytes).await.unwrap();
            }
            finished.await.unwrap();
        };

        let tcp = NameServerConfig {
            socket_addr: address,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            http_endpoint: None,
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: None,
        };
        let opts = ResolverOpts {
            try_tcp_on_error: true,
            ..ResolverOpts::default()
        };
        let name_server =
            GenericNameServer::new(tcp, opts.clone(), TokioConnectionProvider::default());
        let name_servers: Arc<[_]> = Arc::from([name_server]);
        let pool = GenericNameServerPool::from_nameservers_test(
            opts,
            Arc::from([]),
            Arc::clone(&name_servers),
        );
        assert!(!name_servers[0].is_connected());
        let client = async {
            for record in &records {
                let query = Query::query(name.clone(), record.record_type());
                let response = pool
                    .lookup(query.clone(), DnsRequestOptions::default())
                    .first_answer()
                    .await
                    .expect("lookup failed");
                assert_eq!(response.response_code(), ResponseCode::NoError);
                assert_eq!(response.queries(), &[query]);
                assert_eq!(response.answers(), std::slice::from_ref(record));
                assert!(
                    name_servers[0].is_connected(),
                    "NameServer connection state must be shared with the pool"
                );
            }
            done.send(()).unwrap();
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(server, client);
        })
        .await
        .expect("local connection reuse timeout");
    }

    impl GenericNameServerPool<TokioRuntimeProvider> {
        pub(crate) fn tokio_from_config(
            config: &ResolverConfig,
            options: ResolverOpts,
            runtime: TokioRuntimeProvider,
        ) -> Self {
            Self::from_config_with_provider(config, options, GenericConnector::new(runtime))
        }
    }
}
