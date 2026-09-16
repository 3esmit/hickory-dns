use hickory_proto::{
    rr::{
        rdata::{A, AAAA},
        Name, RData, Record, RecordData, RecordType,
    },
    serialize::binary::{BinDecodable, BinEncodable},
};

fn typed_aaaa() -> Record<AAAA> {
    Record::from_rdata(
        Name::from_ascii("www.example.com.").unwrap(),
        60,
        AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
    )
}

#[test]
fn aaaa_data_and_owned_record_report_aaaa() {
    let typed = typed_aaaa();
    assert_eq!(typed.data().record_type(), RecordType::AAAA);
    assert_eq!(typed.record_type(), RecordType::AAAA);
}

#[test]
fn aaaa_borrowed_record_reports_aaaa() {
    let erased = typed_aaaa().into_record_of_rdata();
    let borrowed = erased.try_borrow::<AAAA>().unwrap();
    assert_eq!(borrowed.record_type(), RecordType::AAAA);
    assert_eq!(borrowed.data(), &AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
}

#[test]
fn aaaa_typed_and_erased_wire_records_match() {
    let typed = typed_aaaa();
    let erased = typed.clone().into_record_of_rdata();
    assert_eq!(typed.to_bytes().unwrap(), erased.to_bytes().unwrap());
}

#[test]
fn aaaa_typed_record_round_trips() {
    let typed = typed_aaaa();
    let bytes = typed.to_bytes().unwrap();
    let decoded =
        Record::<RData>::from_bytes(&bytes).expect("typed AAAA must encode a valid DNS record");
    assert_eq!(decoded, typed.into_record_of_rdata());
}

#[test]
fn aaaa_typed_and_erased_display_match() {
    let typed = typed_aaaa();
    assert_eq!(
        typed.to_string(),
        typed.clone().into_record_of_rdata().to_string()
    );
}

#[test]
fn a_record_type_and_wire_format_are_unchanged() {
    let typed = Record::from_rdata(
        Name::from_ascii("www.example.com.").unwrap(),
        60,
        A::new(192, 0, 2, 1),
    );
    assert_eq!(typed.record_type(), RecordType::A);
    let bytes = typed.to_bytes().unwrap();
    assert_eq!(
        Record::<RData>::from_bytes(&bytes).unwrap(),
        typed.into_record_of_rdata()
    );
}
