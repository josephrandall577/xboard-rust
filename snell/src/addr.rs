//! A port of sing's `M.Socksaddr`: an IP address or a domain name with a port.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::{fmt, io};

/// A socks-style address: an IP address or a domain name, plus a port.
///
/// The zero value (no address, no domain) is the invalid address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Socksaddr {
    pub addr: Option<IpAddr>,
    pub port: u16,
    /// Human-readable domain. Use host_bytes for lossless encoding and host
    /// for system resolution; invalid UTF-8 is display-only here.
    pub fqdn: String,
    /// Original non-UTF-8 domain, when present; takes precedence over fqdn.
    pub raw_fqdn: Option<Vec<u8>>,
    /// IPv6 scope/zone, empty for unscoped addresses.
    pub zone: String,
}

fn unwrap_ipv6_address(address: &str) -> &str {
    if address.len() > 2 && address.starts_with('[') && address.ends_with(']') {
        &address[1..address.len() - 1]
    } else {
        address
    }
}

fn to_ipv4_mapped(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    addr.to_ipv4_mapped()
}

impl Socksaddr {
    /// `M.SocksaddrFrom(addr, port)`.
    pub fn from_ip(addr: IpAddr, port: u16) -> Self {
        Socksaddr { addr: Some(addr), port, ..Default::default() }
    }

    /// `M.SocksaddrFromNetIP(addrPort)`.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        let mut result = Self::from_ip(addr.ip(), addr.port());
        if let SocketAddr::V6(addr) = addr
            && addr.scope_id() != 0
        {
            result.zone = addr.scope_id().to_string();
        }
        result
    }

    /// `M.ParseSocksaddrHostPort(host, port)`.
    pub fn parse_host_port(host: &str, port: u16) -> Self {
        let literal = unwrap_ipv6_address(host);
        if let Some((ip, zone)) = literal.split_once('%')
            && !zone.is_empty()
            && let Ok(ip) = ip.parse::<Ipv6Addr>()
        {
            let mut result = Self::from_ip(IpAddr::V6(ip), port);
            result.zone = zone.to_owned();
            return result;
        }
        match literal.parse::<IpAddr>() {
            Ok(addr) => Self::from_ip(addr, port),
            Err(_) => Socksaddr { port, fqdn: host.to_string(), ..Default::default() },
        }
    }

    /// Parses a wire host without substituting invalid UTF-8 bytes.
    pub fn from_host_bytes(host: &[u8], port: u16) -> Self {
        match std::str::from_utf8(host) {
            Ok(host) => Self::parse_host_port(host, port),
            Err(_) => Self {
                port,
                fqdn: String::from_utf8_lossy(host).into_owned(),
                raw_fqdn: Some(host.to_vec()),
                ..Default::default()
            },
        }
    }

    /// Lossless host bytes for CONNECT and UDP request encodings.
    pub fn host_bytes(&self) -> Cow<'_, [u8]> {
        if self.is_ip() {
            Cow::Owned(self.addr_string().into_bytes())
        } else {
            Cow::Borrowed(self.raw_fqdn.as_deref().unwrap_or(self.fqdn.as_bytes()))
        }
    }

    /// Host for system resolution. Never resolve a lossy display string.
    pub fn host(&self) -> io::Result<Cow<'_, str>> {
        if self.is_ip() {
            return Ok(Cow::Owned(self.addr_string()));
        }
        let bytes = self.raw_fqdn.as_deref().unwrap_or(self.fqdn.as_bytes());
        std::str::from_utf8(bytes).map(Cow::Borrowed).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
    }

    /// Parses a host:port pair, including bracketed IPv6 zones.
    pub fn parse(address: &str) -> Self {
        match split_host_port(address) {
            Some((host, port)) => Self::parse_host_port(host, port.parse::<u16>().unwrap_or(0)),
            None => Self::parse_host_port(address, 0),
        }
    }

    pub fn is_ip(&self) -> bool {
        self.addr.is_some()
    }

    /// `Addr.Is4()`: only plain IPv4 addresses.
    pub fn is_ipv4(&self) -> bool {
        matches!(self.addr, Some(IpAddr::V4(_)))
    }

    /// `Addr.Is6()`: IPv6 addresses, including IPv4-mapped ones.
    pub fn is_ipv6(&self) -> bool {
        matches!(self.addr, Some(IpAddr::V6(_)))
    }

    pub fn is_domain(&self) -> bool {
        !self.fqdn.is_empty()
    }

    pub fn is_valid(&self) -> bool {
        self.is_ip() || self.is_domain()
    }

    /// Maps IPv4-mapped IPv6 addresses back to IPv4.
    pub fn unwrap(&self) -> Self {
        if let Some(IpAddr::V6(v6)) = self.addr
            && let Some(v4) = to_ipv4_mapped(&v6)
        {
            return Self::from_ip(IpAddr::V4(v4), self.port);
        }
        self.clone()
    }

    /// The host part: the IP literal or the domain name.
    pub fn addr_string(&self) -> String {
        match self.addr {
            Some(IpAddr::V6(addr)) if !self.zone.is_empty() => format!("{addr}%{}", self.zone),
            Some(addr) => addr.to_string(),
            None => self.fqdn.clone(),
        }
    }

    /// The socket address for an IP with a numeric scope. Named IPv6 zones
    /// return None and must be resolved through host(), retaining the zone.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self.addr? {
            IpAddr::V6(addr) => {
                let scope = if self.zone.is_empty() { 0 } else { self.zone.parse().ok()? };
                Some(SocketAddr::V6(SocketAddrV6::new(addr, self.port, 0, scope)))
            }
            addr => Some(SocketAddr::new(addr, self.port)),
        }
    }
}

fn split_host_port(address: &str) -> Option<(&str, &str)> {
    if let Some(rest) = address.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?;
        if port.contains(':') {
            return None;
        }
        return Some((host, port));
    }
    let index = address.rfind(':')?;
    let host = &address[..index];
    if host.contains(':') {
        return None;
    }
    Some((host, &address[index + 1..]))
}

impl fmt::Display for Socksaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = self.addr_string();
        if host.contains(':') { write!(f, "[{}]:{}", host, self.port) } else { write!(f, "{}:{}", host, self.port) }
    }
}

impl From<SocketAddr> for Socksaddr {
    fn from(addr: SocketAddr) -> Self {
        Self::from_socket_addr(addr)
    }
}
