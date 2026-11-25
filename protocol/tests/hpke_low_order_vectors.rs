//! Consumes the shared R4 C2 artifact `protocol/test-vectors/network-hpke-low-order-v2.txt`, the same
//! bytes the Android strict HPKE public profile test reads. There is no v2 production scanner in this
//! crate yet: `rejected_by_table` below is the artifact's rule written out as a test oracle, so a later
//! production implementation must reproduce exactly these outcomes. Uses only existing dev-dependencies.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

const ARTIFACT: &str = include_str!("../../test-vectors/network-hpke-low-order-v2.txt");
const KEYSETS: &str = include_str!("../../test-vectors/network-hpke-public-keysets-v2.txt");
const TABLE_SHA256_HEX: &str = "b70daac1fd1ad55e4e3504b5295f139e19baed6af7da64190e213b96ea1bbd2e";

fn fixture(input: &'static str) -> BTreeMap<&'static str, &'static str> {
    let mut values = BTreeMap::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("invalid fixture line: {line}"));
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_')),
            "invalid fixture name: {name}"
        );
        assert!(!value.is_empty(), "fixture value must not be empty: {name}");
        assert!(
            values.insert(name, value).is_none(),
            "duplicate fixture field: {name}"
        );
    }
    values
}

fn hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex must contain whole bytes");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid lowercase hex digit"),
    }
}

fn get(values: &BTreeMap<&str, &str>, name: &str) -> Vec<u8> {
    hex(values.get(name).unwrap_or_else(|| panic!("missing {name}")))
}

fn numbered(values: &BTreeMap<&str, &str>, prefix: &str) -> usize {
    values
        .keys()
        .filter(|name| {
            name.strip_prefix(prefix)
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        })
        .count()
}

fn table(values: &BTreeMap<&str, &str>) -> Vec<[u8; 32]> {
    (1..=7)
        .map(|n| {
            get(values, &format!("LOW_ORDER_{n}"))
                .try_into()
                .expect("32-byte row")
        })
        .collect()
}

/// The artifact rule: copy, clear bit 255, compare with every row.
fn rejected_by_table(point: &[u8], rows: &[[u8; 32]]) -> bool {
    assert_eq!(point.len(), 32);
    let mut cleared = [0u8; 32];
    cleared.copy_from_slice(point);
    cleared[31] &= 0x7f;
    rows.contains(&cleared)
}

/// Little-endian 2^255 - 19 + delta for delta in -1..=1 (p-1, p, p+1).
fn near_p(delta: i8) -> [u8; 32] {
    let mut value = [0xffu8; 32];
    value[31] = 0x7f;
    value[0] = (0xed_i16 + i16::from(delta)) as u8;
    value
}

#[test]
fn artifact_pins_seven_rows_digest_aliases_and_near_misses() {
    let values = fixture(ARTIFACT);
    let rows = table(&values);
    assert_eq!(numbered(&values, "LOW_ORDER_"), 7);
    assert_eq!(numbered(&values, "HIGH_BIT_ALIAS_"), 7);
    assert_eq!(numbered(&values, "NEAR_MISS_"), 7);

    let mut hasher = Sha256::new();
    for row in &rows {
        hasher.update(row);
    }
    let digest = hasher.finalize();
    // `&digest[..]` works for both the current sha2 0.10 dev-dependency and a reviewed sha2 0.11.
    assert_eq!(&digest[..], get(&values, "TABLE_SHA256").as_slice());
    assert_eq!(&digest[..], hex(TABLE_SHA256_HEX).as_slice());

    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(rows[0], [0u8; 32]);
    assert_eq!(rows[1], one);
    assert_eq!(rows[4], near_p(-1));
    assert_eq!(rows[5], near_p(0));
    assert_eq!(rows[6], near_p(1));

    for (index, row) in rows.iter().enumerate() {
        let n = index + 1;
        assert_eq!(row[31] & 0x80, 0, "row {n} has bit 255 clear");
        let mut alias = *row;
        alias[31] |= 0x80;
        assert_eq!(get(&values, &format!("HIGH_BIT_ALIAS_{n}")), alias);
        let mut near = *row;
        near[15] ^= 1;
        assert_eq!(get(&values, &format!("NEAR_MISS_{n}")), near);

        assert!(rejected_by_table(row, &rows), "LOW_ORDER_{n}");
        assert!(rejected_by_table(&alias, &rows), "HIGH_BIT_ALIAS_{n}");
        assert!(!rejected_by_table(&near, &rows), "NEAR_MISS_{n}");
    }
}

#[test]
fn generated_points_and_schema_samples_match_the_public_keyset_vectors() {
    let values = fixture(ARTIFACT);
    let keysets = fixture(KEYSETS);
    let rows = table(&values);

    let generated: Vec<_> = keysets
        .keys()
        .filter_map(|name| name.strip_prefix("PUBLIC_KEYSET_"))
        .collect();
    assert_eq!(generated.len(), 8);
    assert_eq!(numbered(&values, "GENERATED_POINT_"), 8);

    // Raw point = the 32 bytes after the single `1a 20` (field 3, length 32) marker of each keyset.
    let point_of = |keyset: &[u8]| -> usize {
        let marks: Vec<_> = keyset
            .windows(2)
            .enumerate()
            .filter(|(_, pair)| *pair == [0x1a, 0x20])
            .map(|(index, _)| index + 2)
            .collect();
        assert_eq!(marks.len(), 1, "exactly one raw-point marker");
        marks[0]
    };
    for id in &generated {
        let keyset = get(&keysets, &format!("PUBLIC_KEYSET_{id}"));
        let at = point_of(&keyset);
        let point = &keyset[at..at + 32];
        assert_eq!(get(&values, &format!("GENERATED_POINT_{id}")), point);
        assert!(!rejected_by_table(point, &rows), "GENERATED_POINT_{id}");
    }

    let base = get(&values, "SCHEMA_BASE");
    assert_eq!(base, get(&keysets, "PUBLIC_KEYSET_1"));
    let at = point_of(&base);
    let substituted = |raw: &[u8]| {
        let mut sample = base.clone();
        sample[at..at + 32].copy_from_slice(raw);
        sample
    };
    for n in 1..=7 {
        for prefix in ["LOW_ORDER_", "HIGH_BIT_ALIAS_", "NEAR_MISS_"] {
            let raw = get(&values, &format!("{prefix}{n}"));
            let sample = get(&values, &format!("SCHEMA_{prefix}{n}"));
            assert_eq!(sample, substituted(&raw), "SCHEMA_{prefix}{n}");
            assert_eq!(
                rejected_by_table(&sample[at..at + 32], &rows),
                prefix != "NEAR_MISS_",
                "SCHEMA_{prefix}{n}"
            );
        }
    }
    assert_eq!(numbered(&values, "SCHEMA_LOW_ORDER_"), 7);
    assert_eq!(numbered(&values, "SCHEMA_HIGH_BIT_ALIAS_"), 7);
    assert_eq!(numbered(&values, "SCHEMA_NEAR_MISS_"), 7);
}
