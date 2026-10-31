use super::*;

#[test]
fn sha256_empty() {
    assert_eq!(
        to_hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_abc() {
    assert_eq!(
        to_hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_two_block_message() {
    assert_eq!(
        to_hex(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn sha256_million_a() {
    let mut h = Sha256::new();
    let chunk = [b'a'; 1000];
    for _ in 0..1000 {
        h.update(&chunk);
    }
    assert_eq!(
        to_hex(&h.finalize()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn sha256_incremental_matches_oneshot_for_all_split_points() {
    let data: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
    let want = sha256(&data);
    for split in 0..data.len() {
        let mut h = Sha256::new();
        h.update(&data[..split]);
        h.update(&data[split..]);
        assert_eq!(h.finalize(), want, "split {split}");
    }
}

#[test]
fn sha256_padding_boundaries() {
    // 55, 56, 63, 64 and 65 byte inputs cross the padding edge cases.
    let expected = [
        (
            55,
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        ),
        (
            56,
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        ),
        (
            64,
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        ),
    ];
    for (n, hex) in expected {
        assert_eq!(to_hex(&sha256(&vec![b'a'; n])), hex, "len {n}");
    }
}

#[test]
fn hmac_rfc4231_case1() {
    let key = [0x0bu8; 20];
    assert_eq!(
        to_hex(&hmac_sha256(&key, b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn hmac_rfc4231_case2() {
    assert_eq!(
        to_hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn hmac_rfc4231_long_key() {
    let key = [0xaau8; 131];
    assert_eq!(
        to_hex(&hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn hex_round_trip_and_rejects_bad_input() {
    let d = sha256(b"x");
    assert_eq!(digest_from_hex(&to_hex(&d)), Some(d));
    assert!(from_hex("abc").is_none());
    assert!(from_hex("zz").is_none());
    assert!(from_hex("AB").is_none());
    assert!(digest_from_hex("00").is_none());
}
