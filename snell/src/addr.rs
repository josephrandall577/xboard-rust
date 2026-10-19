//! A port of sing's `M.Socksaddr`: an IP address or a domain name with a port.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A socks-style address: an IP address or a domain name, plus a port.
///
/// The zero value (no address, no domain) is the invalid address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Socksaddr {
    pub addr: Option<IpAddr>,
    pub port: u16,
    pub fqdn: String,
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
        Socksaddr { addr: Some(addr), port, fqdn: String::new() }
    }

    /// `M.SocksaddrFromNetIP(addrPort)`.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::from_ip(addr.ip(), addr.port())
    }

    /// `M.ParseSocksaddrHostPort(host, port)`.
    pub fn parse_host_port(host: &str, port: u16) -> Self {
        match unwrap_ipv6_address(host).parse::<IpAddr>() {
            Ok(addr) => Self::from_ip(addr, port),
            Err(_) => Socksaddr { addr: None, port, fqdn: host.to_string() },
        }
    }

    /// `M.ParseSocksaddr(address)`.
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
            Some(addr) => addr.to_string(),
            None => self.fqdn.clone(),
        }
    }

    /// The socket address, if this is an IP address.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.addr.map(|addr| SocketAddr::new(addr, self.port))
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
