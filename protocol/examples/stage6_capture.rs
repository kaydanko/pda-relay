//! Stage 6 evidence tool (T04, T14, T15): reads a classic pcap of an emulator's virtual Ethernet
//! (`emulator -tcpdump`), reassembles every TCP connection to the relay port, parses the HTTP upgrade and the
//! WebSocket framing (unmasking client frames), and strictly decodes every binary message with the production
//! v2 codec in its direction. Std only; nothing here is part of the relay binary.
//!
//! ```text
//! cargo run -p pda-relay-protocol --example stage6_capture -- A-traffic.pcap [--port 47821]
//!     [--frames frames.tsv] [--payloads payloads.bin]
//! ```
//! - stdout: per-connection status and totals by direction and tag, error codes, and a final `T04_TAGS=` line;
//! - `--frames`: one TSV row per message (time, connection, direction, tag, length; never content), for T15;
//! - `--payloads`: every unmasked message payload, concatenated, for the T14 `leaks` scan of real bytes.
//!
//! Exit 0 only when every connection reassembled without a gap and every message decoded; 1 otherwise; 2 for
//! usage or unreadable input. A clean result covers only the captured bytes.

use std::collections::BTreeMap;

use pda_relay_protocol::v2::{decode_frame, Direction, FrameV2, WS_PATH, WS_SUBPROTOCOL};

/// One decoded WebSocket application message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    pub connection: usize,
    pub client_to_server: bool,
    /// Capture time (microseconds) of the segment that completed the message.
    pub micros: u64,
    /// The v2 frame tag, or None when the strict codec refused the payload.
    pub tag: Option<u64>,
    pub error_code: Option<u64>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Connection {
    pub client: String,
    pub server: String,
    /// Problems that make this connection's evidence incomplete or invalid.
    pub problems: Vec<String>,
    pub control_frames: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub connections: Vec<Connection>,
    pub messages: Vec<Message>,
    /// Non-IPv4, IPv4 fragments and other packets that could not be examined.
    pub skipped_packets: usize,
}

impl Report {
    pub fn clean(&self) -> bool {
        !self.connections.is_empty()
            && self.connections.iter().all(|c| c.problems.is_empty())
            && self.messages.iter().all(|m| m.tag.is_some())
    }
}

struct Segment {
    seq: u32,
    micros: u64,
    data: Vec<u8>,
}

#[derive(Default)]
struct Half {
    isn: Option<u32>,
    segments: Vec<Segment>,
}

#[derive(Default)]
struct Flow {
    client: Half,
    server: Half,
}

type Endpoint = ([u8; 4], u16);

/// Parses a classic pcap (either byte order, micro- or nanosecond stamps) with Ethernet link type.
pub fn analyze(pcap: &[u8], port: u16) -> Result<Report, String> {
    if pcap.len() < 24 {
        return Err("not a pcap file".into());
    }
    let magic = [pcap[0], pcap[1], pcap[2], pcap[3]];
    let (little, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("not a classic pcap file (pcapng is not supported)".into()),
    };
    let u32_at = |at: usize| -> u32 {
        let b = [pcap[at], pcap[at + 1], pcap[at + 2], pcap[at + 3]];
        if little { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    if u32_at(20) != 1 {
        return Err(format!("link type {} is not Ethernet", u32_at(20)));
    }
    let mut flows: BTreeMap<(Endpoint, Endpoint), Flow> = BTreeMap::new();
    let mut report = Report::default();
    let mut at = 24;
    while at < pcap.len() {
        if at + 16 > pcap.len() {
            return Err("truncated packet header".into());
        }
        let seconds = u64::from(u32_at(at));
        let fraction = u64::from(u32_at(at + 4));
        let captured = u32_at(at + 8) as usize;
        at += 16;
        if at + captured > pcap.len() {
            return Err("truncated packet data".into());
        }
        let micros = seconds * 1_000_000 + if nanos { fraction / 1_000 } else { fraction };
        if !tcp_packet(&pcap[at..at + captured], port, micros, &mut flows) {
            report.skipped_packets += 1;
        }
        at += captured;
    }
    for ((client, server), flow) in flows {
        let index = report.connections.len();
        let mut connection = Connection { client: endpoint(client), server: endpoint(server), ..Connection::default() };
        let mut messages = Vec::new();
        let up = stream(&flow.client, "client", &mut connection.problems);
        let down = stream(&flow.server, "server", &mut connection.problems);
        if let Some(up) = up {
            websocket(index, true, &up, &mut connection, &mut messages);
        }
        if let Some(down) = down {
            websocket(index, false, &down, &mut connection, &mut messages);
        }
        report.connections.push(connection);
        report.messages.extend(messages);
    }
    report.messages.sort_by_key(|m| (m.micros, m.connection, !m.client_to_server));
    Ok(report)
}

fn endpoint((ip, port): Endpoint) -> String {
    format!("{}.{}.{}.{}:{port}", ip[0], ip[1], ip[2], ip[3])
}

/// Records one Ethernet/IPv4/TCP segment of a relay connection; false for anything else.
fn tcp_packet(frame: &[u8], port: u16, micros: u64, flows: &mut BTreeMap<(Endpoint, Endpoint), Flow>) -> bool {
    if frame.len() < 14 || frame[12..14] != [0x08, 0x00] {
        return false;
    }
    let ip = &frame[14..];
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 6 {
        return false;
    }
    let header = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let fragment = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff;
    if header < 20 || total < header || total > ip.len() || fragment != 0 {
        return false;
    }
    let tcp = &ip[header..total];
    if tcp.len() < 20 {
        return false;
    }
    let source = ([ip[12], ip[13], ip[14], ip[15]], u16::from_be_bytes([tcp[0], tcp[1]]));
    let target = ([ip[16], ip[17], ip[18], ip[19]], u16::from_be_bytes([tcp[2], tcp[3]]));
    let to_server = target.1 == port;
    if !to_server && source.1 != port {
        return false;
    }
    let offset = usize::from(tcp[12] >> 4) * 4;
    if offset < 20 || offset > tcp.len() {
        return false;
    }
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let syn = tcp[13] & 0x02 != 0;
    let key = if to_server { (source, target) } else { (target, source) };
    let flow = flows.entry(key).or_default();
    let half = if to_server { &mut flow.client } else { &mut flow.server };
    if syn {
        half.isn = Some(seq);
    }
    let data = &tcp[offset..];
    if !data.is_empty() {
        half.segments.push(Segment { seq, micros, data: data.to_vec() });
    }
    true
}

/// The contiguous byte stream of one direction with, per byte range, the capture time that completed it.
struct Stream {
    bytes: Vec<u8>,
    /// (end offset, micros) of each appended range, ascending.
    times: Vec<(usize, u64)>,
}

impl Stream {
    fn micros_at(&self, end: usize) -> u64 {
        self.times.iter().find(|(stop, _)| *stop >= end).map_or(0, |(_, micros)| *micros)
    }
}

fn stream(half: &Half, side: &str, problems: &mut Vec<String>) -> Option<Stream> {
    if half.segments.is_empty() {
        return None;
    }
    let base = match half.isn {
        Some(isn) => isn.wrapping_add(1),
        None => {
            problems.push(format!("{side}: no SYN captured"));
            half.segments[0].seq
        }
    };
    let mut ordered: Vec<(u64, &Segment)> = half.segments.iter()
        .map(|s| (u64::from(s.seq.wrapping_sub(base)), s))
        .collect();
    ordered.sort_by_key(|(relative, segment)| (*relative, segment.micros));
    let mut out = Stream { bytes: Vec::new(), times: Vec::new() };
    for (relative, segment) in ordered {
        let start = relative as usize;
        let end = start + segment.data.len();
        let have = out.bytes.len();
        if start > have {
            problems.push(format!("{side}: gap of {} bytes at stream offset {have}", start - have));
            break;
        }
        if end <= have {
            continue; // retransmission of bytes already in the stream
        }
        out.bytes.extend_from_slice(&segment.data[have - start..]);
        out.times.push((out.bytes.len(), segment.micros));
    }
    Some(out)
}

fn websocket(connection: usize, client: bool, stream: &Stream, conn: &mut Connection, out: &mut Vec<Message>) {
    let side = if client { "client" } else { "server" };
    let Some(head_end) = stream.bytes.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
        conn.problems.push(format!("{side}: no complete HTTP upgrade header"));
        return;
    };
    let head = String::from_utf8_lossy(&stream.bytes[..head_end]).to_ascii_lowercase();
    let protocol_line = format!("sec-websocket-protocol: {WS_SUBPROTOCOL}");
    let good = if client {
        head.starts_with(&format!("get {WS_PATH} http/1.1\r\n")) && head.contains(&protocol_line)
    } else {
        head.starts_with("http/1.1 101") && head.contains(&protocol_line)
    };
    if !good {
        conn.problems.push(format!("{side}: not a {WS_PATH} upgrade with subprotocol {WS_SUBPROTOCOL}"));
        return;
    }
    let bytes = &stream.bytes;
    let mut at = head_end;
    let mut message: Option<Vec<u8>> = None;
    let mut closed = false;
    while at < bytes.len() {
        if closed {
            conn.problems.push(format!("{side}: data after a close frame"));
            return;
        }
        if at + 2 > bytes.len() {
            conn.problems.push(format!("{side}: truncated frame header at the end of the capture"));
            return;
        }
        let fin = bytes[at] & 0x80 != 0;
        let opcode = bytes[at] & 0x0f;
        let masked = bytes[at + 1] & 0x80 != 0;
        let mut length = u64::from(bytes[at + 1] & 0x7f);
        let mut cursor = at + 2;
        let extended = match length { 126 => 2, 127 => 8, _ => 0 };
        if cursor + extended > bytes.len() {
            conn.problems.push(format!("{side}: truncated frame length at the end of the capture"));
            return;
        }
        if extended > 0 {
            length = bytes[cursor..cursor + extended].iter().fold(0u64, |acc, b| acc << 8 | u64::from(*b));
            cursor += extended;
        }
        if masked != client {
            conn.problems.push(format!("{side}: frame masking is wrong for this direction"));
            return;
        }
        let key = if masked {
            if cursor + 4 > bytes.len() {
                conn.problems.push(format!("{side}: truncated mask at the end of the capture"));
                return;
            }
            let key = [bytes[cursor], bytes[cursor + 1], bytes[cursor + 2], bytes[cursor + 3]];
            cursor += 4;
            Some(key)
        } else {
            None
        };
        let Ok(length) = usize::try_from(length) else {
            conn.problems.push(format!("{side}: impossible frame length"));
            return;
        };
        if cursor + length > bytes.len() {
            conn.problems.push(format!("{side}: truncated frame payload at the end of the capture"));
            return;
        }
        let mut payload = bytes[cursor..cursor + length].to_vec();
        if let Some(key) = key {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[index % 4];
            }
        }
        at = cursor + length;
        match opcode {
            0x0 => match message.as_mut() {
                Some(buffer) => buffer.extend_from_slice(&payload),
                None => {
                    conn.problems.push(format!("{side}: continuation without a started message"));
                    return;
                }
            },
            0x1 => {
                conn.problems.push(format!("{side}: text message (v2 is binary only)"));
                message = Some(payload);
            }
            0x2 => {
                if message.is_some() {
                    conn.problems.push(format!("{side}: new message inside a fragmented one"));
                    return;
                }
                message = Some(payload);
            }
            0x8 => {
                conn.control_frames += 1;
                closed = true;
                continue;
            }
            0x9 | 0xA => {
                conn.control_frames += 1;
                continue;
            }
            other => {
                conn.problems.push(format!("{side}: reserved opcode {other}"));
                return;
            }
        }
        if fin {
            let payload = message.take().unwrap_or_default();
            let direction = if client { Direction::ClientToServer } else { Direction::ServerToClient };
            let (tag, error_code) = match decode_frame(direction, &payload) {
                Ok(frame) => (Some(tag(&frame)), match frame {
                    FrameV2::ServerError { code, .. } => Some(code.code()),
                    _ => None,
                }),
                Err(_) => (None, None),
            };
            out.push(Message { connection, client_to_server: client, micros: stream.micros_at(at), tag, error_code, payload });
        }
    }
    if message.is_some() {
        conn.problems.push(format!("{side}: fragmented message not finished in the capture"));
    }
}

fn tag(frame: &FrameV2<'_>) -> u64 {
    match frame {
        FrameV2::ClientHello { .. } => 0,
        FrameV2::ClientProof { .. } => 1,
        FrameV2::ClientForward { .. } => 3,
        FrameV2::ClientDirectoryPublish { .. } => 5,
        FrameV2::ClientDirectorySearch { .. } => 6,
        FrameV2::Ping { .. } => 8,
        FrameV2::Pong { .. } => 9,
        FrameV2::ServerChallenge { .. } => 16,
        FrameV2::ServerRegistered { .. } => 17,
        FrameV2::ServerDeliver { .. } => 19,
        FrameV2::ServerAccepted { .. } => 20,
        FrameV2::ServerDirectoryResult { .. } => 21,
        FrameV2::ServerError { .. } => 31,
    }
}

/// The text summary printed by the tool (no content, no identifiers beyond the capture's own addresses).
pub fn summary(report: &Report) -> String {
    let mut text = String::new();
    for (index, c) in report.connections.iter().enumerate() {
        let status = if c.problems.is_empty() { "complete".to_string() } else { c.problems.join("; ") };
        text += &format!("connection={index}\tclient={}\tserver={}\tcontrol_frames={}\tstatus={status}\n",
            c.client, c.server, c.control_frames);
    }
    let mut counts: BTreeMap<(&str, String), usize> = BTreeMap::new();
    let mut errors: BTreeMap<u64, usize> = BTreeMap::new();
    for m in &report.messages {
        let direction = if m.client_to_server { "client" } else { "server" };
        let tag = m.tag.map_or_else(|| "INVALID".to_string(), |t| t.to_string());
        *counts.entry((direction, tag)).or_default() += 1;
        if let Some(code) = m.error_code {
            *errors.entry(code).or_default() += 1;
        }
    }
    for ((direction, tag), count) in &counts {
        text += &format!("{direction}\ttag={tag}\tcount={count}\n");
    }
    for (code, count) in &errors {
        text += &format!("server_error_code={code}\tcount={count}\n");
    }
    text += &format!("messages={}\tskipped_packets={}\n", report.messages.len(), report.skipped_packets);
    text += &format!("T04_TAGS={}\n", if report.clean() { "ONLY_V2_FRAMES" } else { "NOT_CLEAN" });
    text
}

/// One TSV row per message: micros, connection, direction, tag, payload length.
pub fn frames_tsv(report: &Report) -> String {
    let mut text = String::from("micros\tconnection\tdirection\ttag\tlength\n");
    for m in &report.messages {
        let tag = m.tag.map_or_else(|| "INVALID".to_string(), |t| t.to_string());
        text += &format!("{}\t{}\t{}\t{tag}\t{}\n", m.micros, m.connection,
            if m.client_to_server { "client" } else { "server" }, m.payload.len());
    }
    text
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut pcap = None;
    let mut port = 47821u16;
    let mut frames = None;
    let mut payloads = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--port" | "--frames" | "--payloads" if index + 1 < args.len() => {
                let value = args[index + 1].clone();
                match args[index].as_str() {
                    "--port" => port = value.parse().unwrap_or_else(|_| usage("port must be 1..65535")),
                    "--frames" => frames = Some(value),
                    _ => payloads = Some(value),
                }
                index += 2;
            }
            other if !other.starts_with("--") && pcap.is_none() => {
                pcap = Some(other.to_string());
                index += 1;
            }
            _ => usage("unknown or incomplete argument"),
        }
    }
    let Some(pcap) = pcap else { usage("a pcap path is required") };
    let bytes = std::fs::read(&pcap).unwrap_or_else(|error| usage(&format!("{pcap}: {error}")));
    let report = analyze(&bytes, port).unwrap_or_else(|error| usage(&format!("{pcap}: {error}")));
    print!("{}", summary(&report));
    if let Some(path) = frames {
        std::fs::write(&path, frames_tsv(&report)).unwrap_or_else(|error| usage(&format!("{path}: {error}")));
    }
    if let Some(path) = payloads {
        let all: Vec<u8> = report.messages.iter().flat_map(|m| m.payload.iter().copied()).collect();
        std::fs::write(&path, all).unwrap_or_else(|error| usage(&format!("{path}: {error}")));
    }
    std::process::exit(if report.clean() { 0 } else { 1 });
}

fn usage(message: &str) -> ! {
    eprintln!("stage6_capture: {message}");
    eprintln!("usage: stage6_capture <capture.pcap> [--port 47821] [--frames out.tsv] [--payloads out.bin]");
    std::process::exit(2);
}
