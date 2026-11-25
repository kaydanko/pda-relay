//! The Stage 6 capture tool (`examples/stage6_capture.rs`) on synthetic pcaps built here: TCP reassembly with
//! split, reordered and retransmitted segments, WebSocket unmasking and fragmentation, strict v2 decoding by
//! direction, and every way the evidence can be incomplete or invalid.

#[allow(dead_code)]
#[path = "../examples/stage6_capture.rs"]
mod capture;

use pda_relay_protocol::v2::{encode_frame, Direction, ErrorCode, FrameV2};

const CLIENT: [u8; 4] = [10, 0, 2, 16];
const SERVER: [u8; 4] = [10, 0, 2, 2];
const PORT: u16 = 47821;

struct Pcap {
    bytes: Vec<u8>,
    nanos: bool,
}

impl Pcap {
    fn new(nanos: bool) -> Self {
        let magic: u32 = if nanos { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
        let mut bytes = magic.to_le_bytes().to_vec();
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        Self { bytes, nanos }
    }

    /// One Ethernet/IPv4/TCP packet at `millis`.
    #[allow(clippy::too_many_arguments)]
    fn tcp(&mut self, millis: u64, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, seq: u32, syn: bool, data: &[u8]) {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(if syn { 0x02 } else { 0x18 });
        tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        tcp.extend_from_slice(data);
        let total = (20 + tcp.len()) as u16;
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&tcp);
        let mut frame = vec![0x52, 0x54, 0, 0x12, 0x34, 0x56, 0x52, 0x55, 0x0a, 0, 2, 2, 0x08, 0x00];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&[0; 4]); // Ethernet padding beyond the IPv4 total length
        self.raw(millis, &frame);
    }

    fn raw(&mut self, millis: u64, frame: &[u8]) {
        let fraction = if self.nanos { (millis % 1000) * 1_000_000 } else { (millis % 1000) * 1000 };
        self.bytes.extend_from_slice(&((millis / 1000) as u32).to_le_bytes());
        self.bytes.extend_from_slice(&(fraction as u32).to_le_bytes());
        self.bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        self.bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        self.bytes.extend_from_slice(frame);
    }
}

fn ws(opcode: u8, fin: bool, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![if fin { 0x80 } else { 0 } | opcode];
    let bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(bit | n as u8),
        n if n <= 0xffff => {
            out.push(bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(bit | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

const REQUEST: &[u8] = b"GET /v2/ws HTTP/1.1\r\nHost: 10.0.2.2:47821\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: pda-relay.cbor.v2\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: pda-relay.cbor.v2\r\n\r\n";

struct Session {
    ping: Vec<u8>,
    error: Vec<u8>,
    pong: Vec<u8>,
    client_stream: Vec<u8>,
    server_stream: Vec<u8>,
}

/// A client PING (masked; [write] splits it across TCP segments), a server
/// RECIPIENT_OFFLINE error, a server PING control frame and a server PONG fragmented into two frames.
fn session(request: &[u8], client_mask: Option<[u8; 4]>) -> Session {
    let ping = encode_frame(Direction::ClientToServer, &FrameV2::Ping { nonce: 7 }).unwrap();
    let error = encode_frame(Direction::ServerToClient,
        &FrameV2::ServerError { code: ErrorCode::RecipientOffline, related_packet_id: Some([1; 16]) }).unwrap();
    let pong = encode_frame(Direction::ServerToClient, &FrameV2::Pong { nonce: 7 }).unwrap();
    let mut client_stream = request.to_vec();
    client_stream.extend(ws(0x2, true, client_mask, &ping));
    let mut server_stream = RESPONSE.to_vec();
    server_stream.extend(ws(0x2, true, None, &error));
    server_stream.extend(ws(0x9, true, None, b"hb"));
    server_stream.extend(ws(0x2, false, None, &pong[..1]));
    server_stream.extend(ws(0x0, true, None, &pong[1..]));
    Session { ping, error, pong, client_stream, server_stream }
}

/// Writes the session: the client stream in three segments sent out of order with one retransmission, the
/// server stream in two segments, and unrelated traffic on another port.
fn write(pcap: &mut Pcap, s: &Session, drop_client_middle: bool) {
    pcap.tcp(1_000, CLIENT, 40000, SERVER, PORT, 1_000, true, &[]);
    pcap.tcp(1_001, SERVER, PORT, CLIENT, 40000, 5_000, true, &[]);
    let c = &s.client_stream;
    let (a, b) = (REQUEST.len().min(c.len()) / 2, c.len() - 3);
    pcap.tcp(1_002, CLIENT, 40000, SERVER, PORT, 1_001, false, &c[..a]);
    pcap.tcp(1_003, CLIENT, 40000, SERVER, PORT, 1_001 + b as u32, false, &c[b..]);
    if !drop_client_middle {
        pcap.tcp(1_004, CLIENT, 40000, SERVER, PORT, 1_001 + a as u32, false, &c[a..b]);
        pcap.tcp(1_005, CLIENT, 40000, SERVER, PORT, 1_001 + a as u32, false, &c[a..b]); // retransmission
    }
    let d = &s.server_stream;
    let half = d.len() / 2;
    pcap.tcp(1_006, SERVER, PORT, CLIENT, 40000, 5_001, false, &d[..half]);
    pcap.tcp(1_250, SERVER, PORT, CLIENT, 40000, 5_001 + half as u32, false, &d[half..]);
    pcap.tcp(1_300, CLIENT, 5555, SERVER, 443, 9, false, b"not relay traffic");
}

#[test]
fn a_complete_session_reassembles_unmasks_and_decodes_only_v2_frames() {
    for nanos in [false, true] {
        let s = session(REQUEST, Some([0x11, 0x22, 0x33, 0x44]));
        let mut pcap = Pcap::new(nanos);
        write(&mut pcap, &s, false);
        let report = capture::analyze(&pcap.bytes, PORT).unwrap();
        assert_eq!(report.connections.len(), 1);
        assert_eq!(report.connections[0].problems, Vec::<String>::new());
        assert_eq!(report.connections[0].client, "10.0.2.16:40000");
        assert_eq!(report.connections[0].control_frames, 1);
        assert_eq!(report.skipped_packets, 1, "the unrelated packet is skipped");
        assert!(report.clean());
        let tags: Vec<(bool, Option<u64>)> = report.messages.iter().map(|m| (m.client_to_server, m.tag)).collect();
        assert_eq!(tags, [(true, Some(8)), (false, Some(31)), (false, Some(9))]);
        assert_eq!(report.messages[0].payload, s.ping, "client payload unmasked");
        assert_eq!(report.messages[1].payload, s.error);
        assert_eq!(report.messages[1].error_code, Some(5));
        assert_eq!(report.messages[2].payload, s.pong, "fragments joined");
        assert_eq!(report.messages[2].micros, 1_250_000, "time of the segment that completed the message");
        let text = capture::summary(&report);
        assert!(text.contains("client\ttag=8\tcount=1\n"));
        assert!(text.contains("server_error_code=5\tcount=1\n"));
        assert!(text.ends_with("T04_TAGS=ONLY_V2_FRAMES\n"));
        let tsv = capture::frames_tsv(&report);
        assert_eq!(tsv.lines().count(), 4);
        assert!(tsv.lines().all(|line| line.split('\t').count() == 5), "no content column");
    }
}

#[test]
fn a_missing_segment_is_reported_as_a_gap() {
    let s = session(REQUEST, Some([1, 2, 3, 4]));
    let mut pcap = Pcap::new(false);
    write(&mut pcap, &s, true);
    let report = capture::analyze(&pcap.bytes, PORT).unwrap();
    assert!(!report.clean());
    assert!(report.connections[0].problems.iter().any(|p| p.starts_with("client: gap of")), "{:?}", report.connections[0].problems);
    assert!(capture::summary(&report).ends_with("T04_TAGS=NOT_CLEAN\n"));
}

#[test]
fn a_frame_for_the_other_direction_is_invalid() {
    // A server frame sent by the client: strictly refused by the client-direction codec.
    let accepted = encode_frame(Direction::ServerToClient, &FrameV2::ServerAccepted { packet_id: [2; 16] }).unwrap();
    let mut s = session(REQUEST, Some([9, 9, 9, 9]));
    s.client_stream = REQUEST.to_vec();
    s.client_stream.extend(ws(0x2, true, Some([9, 9, 9, 9]), &accepted));
    let mut pcap = Pcap::new(false);
    write(&mut pcap, &s, false);
    let report = capture::analyze(&pcap.bytes, PORT).unwrap();
    assert!(report.connections[0].problems.is_empty());
    assert_eq!(report.messages.iter().filter(|m| m.tag.is_none()).count(), 1);
    assert!(!report.clean());
    assert!(capture::summary(&report).contains("client\ttag=INVALID\tcount=1\n"));
}

#[test]
fn an_unmasked_client_frame_or_another_subprotocol_is_a_problem() {
    let unmasked = session(REQUEST, None);
    let mut pcap = Pcap::new(false);
    write(&mut pcap, &unmasked, false);
    let report = capture::analyze(&pcap.bytes, PORT).unwrap();
    assert!(report.connections[0].problems.iter().any(|p| p.contains("masking")), "{:?}", report.connections[0].problems);

    let other = b"GET /v2/ws HTTP/1.1\r\nSec-WebSocket-Protocol: pda-relay.cbor.v1\r\n\r\n";
    let mut pcap = Pcap::new(false);
    write(&mut pcap, &session(other, Some([1, 1, 1, 1])), false);
    let report = capture::analyze(&pcap.bytes, PORT).unwrap();
    assert!(report.connections[0].problems.iter().any(|p| p.starts_with("client: not a /v2/ws upgrade")));
    assert!(!report.clean());
}

#[test]
fn bad_files_and_captures_without_relay_traffic_are_not_evidence() {
    assert!(capture::analyze(b"short", PORT).is_err());
    assert!(capture::analyze(&[0x0a, 0x0d, 0x0d, 0x0a].repeat(8), PORT).is_err(), "pcapng is refused");
    let mut pcap = Pcap::new(false);
    pcap.tcp(1, CLIENT, 5555, SERVER, 443, 9, false, b"other");
    let report = capture::analyze(&pcap.bytes, PORT).unwrap();
    assert!(report.connections.is_empty());
    assert!(!report.clean(), "no relay connection is never clean");
    let mut truncated = Pcap::new(false).bytes;
    truncated.extend_from_slice(&[1, 2, 3]);
    assert!(capture::analyze(&truncated, PORT).is_err());
}
