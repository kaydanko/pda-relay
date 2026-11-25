use pda_relay_protocol::Limits as ProtocolLimits;
use std::{env, io, net::SocketAddr, time::Duration};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub max_connections: usize,
    pub max_frame_bytes: usize,
    pub max_payload_bytes: usize,
    pub outbound_queue_messages: usize,
    pub packets_per_second: u32,
    pub hello_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub malformed_frame_threshold: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080"
                .parse()
                .expect("valid default listen address"),
            max_connections: 32,
            max_frame_bytes: 16_384,
            max_payload_bytes: 16_000,
            outbound_queue_messages: 16,
            packets_per_second: 20,
            hello_timeout: Duration::from_secs(5),
            heartbeat_interval: Duration::from_secs(15),
            heartbeat_timeout: Duration::from_secs(45),
            malformed_frame_threshold: 3,
        }
    }
}

impl Config {
    pub fn from_env() -> io::Result<Self> {
        let mut config = Self::default();
        config.listen = parse_env("PDA_RELAY_LISTEN", config.listen)?;
        config.max_connections = parse_env("PDA_RELAY_MAX_CONNECTIONS", config.max_connections)?;
        config.max_frame_bytes = parse_env("PDA_RELAY_MAX_FRAME_BYTES", config.max_frame_bytes)?;
        config.max_payload_bytes =
            parse_env("PDA_RELAY_MAX_PAYLOAD_BYTES", config.max_payload_bytes)?;
        config.outbound_queue_messages = parse_env(
            "PDA_RELAY_OUTBOUND_QUEUE_MESSAGES",
            config.outbound_queue_messages,
        )?;
        config.packets_per_second =
            parse_env("PDA_RELAY_PACKETS_PER_SECOND", config.packets_per_second)?;
        config.hello_timeout = Duration::from_secs(parse_env(
            "PDA_RELAY_HELLO_TIMEOUT_SECONDS",
            config.hello_timeout.as_secs(),
        )?);
        config.heartbeat_interval = Duration::from_secs(parse_env(
            "PDA_RELAY_HEARTBEAT_INTERVAL_SECONDS",
            config.heartbeat_interval.as_secs(),
        )?);
        config.heartbeat_timeout = Duration::from_secs(parse_env(
            "PDA_RELAY_HEARTBEAT_TIMEOUT_SECONDS",
            config.heartbeat_timeout.as_secs(),
        )?);
        config.malformed_frame_threshold = parse_env(
            "PDA_RELAY_MALFORMED_FRAME_THRESHOLD",
            config.malformed_frame_threshold,
        )?;
        config.validate()?;
        Ok(config)
    }

    pub fn protocol_limits(&self) -> ProtocolLimits {
        ProtocolLimits {
            max_frame_bytes: self.max_frame_bytes,
            max_payload_bytes: self.max_payload_bytes,
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.max_connections == 0
            || self.max_frame_bytes == 0
            || self.max_payload_bytes == 0
            || self.outbound_queue_messages == 0
            || self.packets_per_second == 0
            || self.malformed_frame_threshold == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay limits must be greater than zero",
            ));
        }
        if self.max_payload_bytes > self.max_frame_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max payload bytes cannot exceed max frame bytes",
            ));
        }
        if self.heartbeat_interval >= self.heartbeat_timeout {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "heartbeat interval must be shorter than heartbeat timeout",
            ));
        }
        Ok(())
    }
}

fn parse_env<T>(name: &str, default: T) -> io::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => value.parse().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid {name}: {error}"),
            )
        }),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cannot read {name}: {error}"),
        )),
    }
}
