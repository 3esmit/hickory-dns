//! Runtime-independent wire fixture for resolver search and cache tests.

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    config::NameServerConfig,
    proto::{
        op::{Message, MessageType, OpCode, ResponseCode},
        rr::{
            rdata::{A, SOA},
            DNSClass, Name, RData, Record,
        },
        xfer::Protocol,
    },
};

pub(crate) struct LocalDns {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Vec<Name>>>,
}

impl LocalDns {
    pub(crate) fn new() -> Self {
        Self::with_answer(RData::A(A::new(93, 184, 215, 14)))
    }

    pub(crate) fn with_answer(answer: RData) -> Self {
        assert!(matches!(answer, RData::A(_) | RData::AAAA(_)));
        Self::with_responder(move |request| {
            let query = &request.queries()[0];
            assert_eq!(query.query_type(), answer.record_type());
            let mut response = Self::response(request);
            if query.name() == &Name::from_ascii("www.example.com.").unwrap() {
                response.add_answer(Record::from_rdata(query.name().clone(), 60, answer.clone()));
            } else {
                response.set_response_code(ResponseCode::NXDomain);
                // An SOA is needed to exercise negative caching of search misses.
                response.add_name_server(Record::from_rdata(
                    Name::from_ascii("example.com.").unwrap(),
                    60,
                    RData::SOA(SOA::new(
                        Name::from_ascii("ns.example.com.").unwrap(),
                        Name::from_ascii("hostmaster.example.com.").unwrap(),
                        1,
                        60,
                        60,
                        60,
                        60,
                    )),
                ));
            }
            response
        })
    }

    pub(crate) fn response(request: &Message) -> Message {
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true)
            .add_query(request.queries()[0].clone());
        response
    }

    pub(crate) fn with_responder(responder: impl Fn(&Message) -> Message + Send + 'static) -> Self {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = socket.local_addr().unwrap();
        // Also bounds cleanup if the shutdown wake-up datagram cannot be delivered.
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut names = Vec::new();
            let mut bytes = [0; 4096];
            while !worker_stop.load(Ordering::Acquire) {
                let (length, peer) = match socket.recv_from(&mut bytes) {
                    Ok(received) => received,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue
                    }
                    Err(error) => panic!("local DNS receive failed: {error}"),
                };
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                let request = Message::from_vec(&bytes[..length]).unwrap();
                assert_eq!(request.message_type(), MessageType::Query);
                assert_eq!(request.op_code(), OpCode::Query);
                assert_eq!(request.queries().len(), 1);
                let query = &request.queries()[0];
                assert_eq!(query.query_class(), DNSClass::IN);
                names.push(query.name().clone());
                let response = responder(&request);
                socket.send_to(&response.to_vec().unwrap(), peer).unwrap();
            }
            names
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }

    pub(crate) fn name_servers(&self) -> Vec<NameServerConfig> {
        vec![NameServerConfig::new(self.address, Protocol::Udp)]
    }

    pub(crate) fn assert_queries(mut self, expected: &[&str]) {
        let names = self.shutdown().unwrap();
        let expected: Vec<_> = expected
            .iter()
            .map(|name| Name::from_ascii(name).unwrap())
            .collect();
        assert_eq!(names, expected, "wire query order, including cache reuse");
    }

    fn shutdown(&mut self) -> thread::Result<Vec<Name>> {
        self.stop.store(true, Ordering::Release);
        // Wake the blocking receiver without introducing sleeps or a detached worker.
        if let Ok(wake) = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)) {
            let _ = wake.send_to(&[], self.address);
        }
        self.worker.take().unwrap().join()
    }
}

impl Drop for LocalDns {
    fn drop(&mut self) {
        if self.worker.is_some() {
            if let Err(error) = self.shutdown() {
                if !thread::panicking() {
                    std::panic::resume_unwind(error);
                }
            }
        }
    }
}
