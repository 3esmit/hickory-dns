//! Local wire replies shared by the UDP and TCP client examples.

use std::{future::Future, time::Duration};

use crate::proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{rdata::A, Name, RData, Record, RecordType},
    ProtoError,
};

pub(crate) const NAME: &str = "www.example.com.";

pub(crate) fn answer() -> Record {
    Record::from_rdata(
        Name::from_ascii(NAME).unwrap(),
        60,
        RData::A(A::new(93, 184, 215, 14)),
    )
}

pub(crate) fn reply(bytes: &[u8]) -> Vec<u8> {
    let request = Message::from_vec(bytes).unwrap();
    let query = Query::query(Name::from_ascii(NAME).unwrap(), RecordType::A);
    assert_eq!(request.message_type(), MessageType::Query);
    assert_eq!(request.op_code(), OpCode::Query);
    assert_eq!(request.queries(), std::slice::from_ref(&query));
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .add_query(query)
        .add_answer(answer());
    response.to_vec().unwrap()
}

pub(crate) async fn drive(
    background: impl Future<Output = Result<(), ProtoError>>,
    queries: impl Future<Output = ()>,
) {
    tokio::select! {
        _ = queries => {}
        result = background => panic!("client driver ended before queries: {result:?}"),
    }
}

pub(crate) async fn run(server: impl Future<Output = ()>, client: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server, client);
    })
    .await
    .expect("local client test timeout");
}
