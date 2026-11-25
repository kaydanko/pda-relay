//! Allocation discipline of the relay v2 codec, measured with a per-thread counting allocator in this
//! test binary only: invalid or oversized caller fields are refused before ANY allocation, a valid frame
//! is encoded with exactly one allocation of exactly the output size, and decoding never allocates.
#![allow(unused_unsafe)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;

use pda_relay_protocol::v2::{decode_frame, encode_frame, Direction, FrameV2, MAX_NONCE};

struct Counting;

thread_local! {
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

fn record(size: usize) {
    let _ = CALLS.try_with(|calls| calls.set(calls.get() + 1));
    let _ = BYTES.try_with(|bytes| bytes.set(bytes.get() + size));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// (result, allocation calls, allocated bytes) of `f` on this thread.
fn measured<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    CALLS.with(|calls| calls.set(0));
    BYTES.with(|bytes| bytes.set(0));
    let result = f();
    (result, CALLS.with(Cell::get), BYTES.with(Cell::get))
}

const FRAMES: &str = include_str!("../../test-vectors/network-relay-v2-frames.txt");
const C2S: Direction = Direction::ClientToServer;
const S2C: Direction = Direction::ServerToClient;
const HUGE: usize = 8 * 1024 * 1024;

fn values() -> BTreeMap<&'static str, Vec<u8>> {
    FRAMES
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (name, value) = line.split_once('=').expect("fixture line");
            let bytes = (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
                .collect();
            (name, bytes)
        })
        .collect()
}

#[test]
fn oversized_or_inconsistent_caller_fields_are_refused_before_any_allocation() {
    let values = values();
    let huge = vec![0x5au8; HUGE];
    let hello_bytes = &values["C2S_HELLO"];
    let FrameV2::ClientHello { root_spki, authorization, client_nonce } = decode_frame(C2S, hello_bytes).unwrap() else {
        panic!("HELLO expected")
    };
    let forward_bytes = &values["C2S_FORWARD"];
    let FrameV2::ClientForward { envelope } = decode_frame(C2S, forward_bytes).unwrap() else {
        panic!("FORWARD expected")
    };

    let mut altered_epoch = authorization;
    altered_epoch.epoch[0] ^= 1;
    let mut oversized_tbs = authorization;
    oversized_tbs.tbs = &huge;
    let mut foreign_header = envelope;
    foreign_header.header.recipient_root[0] ^= 1;
    let mut oversized_ciphertext = envelope;
    oversized_ciphertext.ciphertext = &huge;

    let refused: Vec<(&str, Direction, FrameV2<'_>)> = vec![
        ("huge root SPKI", C2S, FrameV2::ClientHello { root_spki: &huge, authorization, client_nonce }),
        ("short root SPKI", C2S, FrameV2::ClientHello { root_spki: &root_spki[..90], authorization, client_nonce }),
        ("huge authorization envelope", C2S, FrameV2::ClientHello {
            root_spki,
            authorization: pda_relay_protocol::v2::ActivationV2 { envelope: &huge, ..authorization },
            client_nonce,
        }),
        ("authorization fields not from its envelope", C2S, FrameV2::ClientHello { root_spki, authorization: altered_epoch, client_nonce }),
        ("authorization with a foreign huge TBS", C2S, FrameV2::ClientHello { root_spki, authorization: oversized_tbs, client_nonce }),
        ("huge proof signature", C2S, FrameV2::ClientProof { signature_der: &huge }),
        ("non-canonical proof signature", C2S, FrameV2::ClientProof { signature_der: &[0x30, 0x06, 2, 1, 0, 2, 1, 1] }),
        ("huge packet envelope", C2S, FrameV2::ClientForward {
            envelope: pda_relay_protocol::v2::PacketEnvelopeV2 { original: &huge, ..envelope },
        }),
        ("header not from its envelope", C2S, FrameV2::ClientForward { envelope: foreign_header }),
        ("foreign huge ciphertext", S2C, FrameV2::ServerDeliver { envelope: oversized_ciphertext }),
        ("nonce above the R4 maximum", C2S, FrameV2::Ping { nonce: MAX_NONCE + 1 }),
        ("server frame in the client direction", C2S, FrameV2::ServerAccepted { packet_id: [1; 16] }),
    ];
    for (name, direction, frame) in &refused {
        let (result, calls, bytes) = measured(|| encode_frame(*direction, frame));
        assert!(result.is_err(), "{name} must be refused");
        assert_eq!((calls, bytes), (0, 0), "{name} allocated before validation");
    }
}

#[test]
fn a_valid_frame_is_encoded_with_one_exact_allocation() {
    let values = values();
    for (name, direction) in [
        ("C2S_HELLO", C2S),
        ("C2S_FORWARD", C2S),
        ("S2C_DELIVER", S2C),
        ("S2C_ERROR_RECIPIENT_OFFLINE", S2C),
        ("BOTH_PING_MAX", C2S),
    ] {
        let bytes = &values[name];
        let frame = decode_frame(direction, bytes).unwrap();
        let (encoded, calls, allocated) = measured(|| encode_frame(direction, &frame).unwrap());
        assert_eq!(&encoded, bytes, "{name}");
        assert_eq!((calls, allocated), (1, bytes.len()), "{name}");
        assert_eq!(encoded.capacity(), bytes.len(), "{name}");
    }
}

#[test]
fn decoding_valid_and_rejected_artifact_frames_never_allocates() {
    let values = values();
    for (name, bytes) in &values {
        let directions: &[Direction] = match name.split('_').next().unwrap() {
            "C2S" => &[C2S],
            "S2C" => &[S2C],
            "BOTH" | "REJECT" => &[C2S, S2C],
            _ => continue,
        };
        for direction in directions {
            let (_, calls, allocated) = measured(|| decode_frame(*direction, bytes).is_ok());
            assert_eq!((calls, allocated), (0, 0), "{name} {direction:?}");
        }
    }
}
