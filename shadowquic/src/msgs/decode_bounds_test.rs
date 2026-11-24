//! Lengths on the wire are chosen by the peer: decoding must not trust them
//! with memory before the bytes have arrived, and encoding must not put a
//! length on the wire that differs from what follows it.
use super::{
    SDecode, SEncode,
    socks5::{SocksAddr, VarVec},
    squic::{ConnStats, UserStats},
};
use crate::error::SError;

#[tokio::test]
async fn vec_length_prefix_does_not_reserve_memory_up_front() {
    // u32::MAX elements of 64 KiB each (256 TiB) exceed any address space.
    let mut wire: &[u8] = &[0xff, 0xff, 0xff, 0xff];
    assert!(Vec::<[u8; 1 << 16]>::decode(&mut wire).await.is_err());

    let mut wire: &[u8] = &[0xff, 0xff, 0xff, 0xff, 1, 2, 3];
    assert!(Vec::<UserStats>::decode(&mut wire).await.is_err());
    let mut wire: &[u8] = &[0xff, 0xff, 0xff, 0xff, b'a', b'b'];
    assert!(String::decode(&mut wire).await.is_err());
}

#[tokio::test]
async fn vec_decodes_what_was_encoded() {
    let names: Vec<String> = (0..3000).map(|i| format!("user-{i}")).collect();
    let mut wire = Vec::new();
    names.encode(&mut wire).await.unwrap();
    assert_eq!(Vec::<String>::decode(&mut &wire[..]).await.unwrap(), names);
}

#[tokio::test]
async fn size_tagged_struct_rejects_an_absurd_size() {
    let mut wire: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0, 0];
    assert!(matches!(
        ConnStats::decode(&mut wire).await,
        Err(SError::ProtocolViolation)
    ));
}

#[tokio::test]
async fn size_tagged_struct_keeps_its_compatibility_rules() {
    let stats = ConnStats {
        lost_packets: 1,
        sent_packets: 2,
        rtt: 3.5,
        current_mtu: 1400,
    };
    let mut wire = Vec::new();
    stats.encode(&mut wire).await.unwrap();
    assert!(ConnStats::decode(&mut &wire[..]).await.unwrap() == stats);

    // A newer peer appends fields: the unknown tail is skipped.
    let mut longer = wire.clone();
    let len = u32::from_be_bytes(longer[..4].try_into().unwrap()) + 5;
    longer[..4].copy_from_slice(&len.to_be_bytes());
    longer.extend_from_slice(&[9; 5]);
    longer.push(0x42);
    let mut reader = &longer[..];
    assert!(ConnStats::decode(&mut reader).await.unwrap() == stats);
    assert_eq!(reader, &[0x42]);

    // An older peer sends fewer fields: the missing tail reads as zero.
    let mut shorter = wire.clone();
    let len = u32::from_be_bytes(shorter[..4].try_into().unwrap()) - 2;
    shorter[..4].copy_from_slice(&len.to_be_bytes());
    shorter.truncate(4 + len as usize);
    let decoded = ConnStats::decode(&mut &shorter[..]).await.unwrap();
    assert_eq!(decoded.current_mtu, 0);
    assert_eq!(decoded.sent_packets, 2);

    // A size that promises more than arrives is an error.
    let mut cut = wire.clone();
    cut.truncate(wire.len() - 1);
    assert!(ConnStats::decode(&mut &cut[..]).await.is_err());
}

#[tokio::test]
async fn overlong_domain_is_refused_not_truncated() {
    let name = "a".repeat(300);
    let mut wire = Vec::new();
    let addr = SocksAddr::from_domain(name.clone(), 443);
    assert!(
        addr.encode(&mut wire).await.is_err(),
        "a 300 byte name went out as {} bytes",
        wire.len()
    );
    let mut wire = Vec::new();
    assert!(
        VarVec::from(name.into_bytes())
            .encode(&mut wire)
            .await
            .is_err()
    );

    let longest = "b".repeat(255);
    let mut wire = Vec::new();
    SocksAddr::from_domain(longest.clone(), 443)
        .encode(&mut wire)
        .await
        .unwrap();
    let decoded = SocksAddr::decode(&mut &wire[..]).await.unwrap();
    assert_eq!(decoded, SocksAddr::from_domain(longest, 443));
}

#[tokio::test]
async fn length_that_disagrees_with_the_contents_is_refused() {
    let mut wire = Vec::new();
    let longer_len = VarVec {
        len: 5,
        contents: vec![1, 2],
    };
    assert!(longer_len.encode(&mut wire).await.is_err());
    let shorter_len = VarVec {
        len: 1,
        contents: vec![1, 2],
    };
    assert!(shorter_len.encode(&mut wire).await.is_err());
}
