// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// Exercise the README client flow with deterministic local replies.
#[tokio::test]
async fn readme_example() {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use crate::client::{Client, ClientHandle};
    use crate::proto::rr::{rdata::A, DNSClass, Name, RData, Record, RecordType};
    use crate::proto::runtime::TokioRuntimeProvider;
    use crate::proto::udp::UdpClientStream;
    use crate::proto::xfer::DnsResponse;
    use crate::wire_fixture;

    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let serving = async {
        let mut buffer = [0; 4096];
        for _ in 0..2 {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let reply = wire_fixture::reply(&buffer[..length]);
            socket.send_to(&reply, peer).await.unwrap();
        }
    };
    let querying = async {
        let conn = UdpClientStream::builder(address, TokioRuntimeProvider::default()).build();
        let (mut client, bg) = Client::connect(conn).await.unwrap();
        wire_fixture::drive(bg, async {
            for _ in 0..2 {
                // Specify the name, note the final '.' which specifies it's an FQDN
                let name = Name::from_str("www.example.com.").unwrap();

                // NOTE: see 'Setup a connection' example above
                // Send the query and get a message response, see RecordType for all supported options
                let response: DnsResponse = client
                    .query(name, DNSClass::IN, RecordType::A)
                    .await
                    .unwrap();

                // Messages are the packets sent between client and server in DNS, DnsResonse's can be
                //  dereferenced to a Message. There are many fields to a Message, It's beyond the scope
                //  of these examples to explain them. See hickory_dns::op::message::Message for more details.
                //  generally we will be interested in the Message::answers
                let answers: &[Record] = response.answers();
                assert_eq!(answers, &[wire_fixture::answer()]);

                // Records are generic objects which can contain any data.
                //  In order to access it we need to first check what type of record it is
                //  In this case we are interested in A, IPv4 address
                if let RData::A(A(ref ip)) = answers[0].data() {
                    assert_eq!(*ip, Ipv4Addr::new(93, 184, 215, 14))
                } else {
                    panic!("unexpected result")
                }
            }
        })
        .await;
    };
    wire_fixture::run(serving, querying).await;
}
