#![cfg(feature = "dnssec")]

mod local_signed_fixture;

use hickory_client::client::{ClientHandle, DnssecClient};
use hickory_proto::{
    dnssec::{Nsec3HashAlgorithm, Proof},
    op::ResponseCode,
    rr::{DNSClass, Name, RecordType},
    runtime::TokioRuntimeProvider,
    tcp::TcpClientStream,
    xfer::DnsMultiplexer,
};
use hickory_server::dnssec::NxProofKind;
use local_signed_fixture::{drive, SignedDns};
use std::sync::Arc;

#[tokio::test]
async fn local_nsec3_records_are_secure() {
    SignedDns::new(NxProofKind::Nsec3 {
        algorithm: Nsec3HashAlgorithm::default(),
        salt: Arc::from([1, 2, 3]),
        iterations: 1,
    })
    .await
    .run(|address, anchor| async move {
        let (stream, sender) =
            TcpClientStream::new(address, None, None, TokioRuntimeProvider::default());
        let (mut client, background) =
            DnssecClient::builder(DnsMultiplexer::new(stream, sender, None))
                .trust_anchor(anchor)
                .build()
                .await
                .unwrap();
        drive(background, async {
            let response = client
                .query(
                    Name::from_ascii("a.b.c.example.com.").unwrap(),
                    DNSClass::IN,
                    RecordType::NS,
                )
                .await
                .unwrap();
            assert_eq!(response.response_code(), ResponseCode::NXDomain);
            assert!(response.answers().is_empty());
            assert!(response
                .name_servers()
                .iter()
                .any(|record| record.record_type() == RecordType::NSEC3));
            for record in response.name_servers() {
                let copies = response
                    .name_servers()
                    .iter()
                    .filter(|other| *other == record)
                    .count();
                assert_eq!(record.proof(), Proof::Secure, "copies={copies}: {record:?}");
            }
        })
        .await;
    })
    .await;
}
