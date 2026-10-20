//! Address encodings used by snell requests and UDP frames.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::addr::Socksaddr;
use crate::buf::Buffer;
use crate::error::{self, ErrorCode};
use crate::{ADDRESS_TYPE_IPV4, ADDRESS_TYPE_IPV6, UDP_COMMAND_FORWARD};

pub(crate) fn read_sock_string(reader: &mut Buffer) -> io::Result<String> {
    let mut len = [0u8; 1];
    reader.read_full(&mut len)?;
    let mut bytes = vec![0u8; len[0] as usize];
    reader.read_full(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn put_port(buffer: &mut Buffer, port: u16) {
    buffer.extend(2).copy_from_slice(&port.to_be_bytes());
}

/// Writes a CONNECT target.
///
/// Surge 6.7.0 (11520): SNConnectorV4::targetHandshakeData: CONNECT targets are host strings even for literal IPs.
pub fn write_connect_address(buffer: &mut Buffer, destination: &Socksaddr) -> io::Result<()> {
    let host = destination.host_bytes();
    if host.len() > 255 {
        return Err(error::new_invalid("snell: host too long"));
    }
    buffer.write_byte(host.len() as u8);
    buffer.write_all(&host);
    put_port(buffer, destination.port);
    Ok(())
}

pub fn read_connect_address(reader: &mut Buffer) -> io::Result<Socksaddr> {
    let len = reader.read_byte()? as usize;
    let host = reader.read_bytes(len)?.to_vec();
    let mut port = [0u8; 2];
    reader.read_full(&mut port)?;
    Ok(Socksaddr::from_host_bytes(&host, u16::from_be_bytes(port)))
}

/// `udpIPSerializer.WriteAddrPort`: family 0x04 / 0x06, address, port.
fn write_ip_addr_port(buffer: &mut Buffer, destination: &Socksaddr) -> io::Result<()> {
    match destination.addr {
        Some(IpAddr::V4(addr)) => {
            buffer.write_byte(ADDRESS_TYPE_IPV4);
            buffer.write_all(&addr.octets());
        }
        Some(IpAddr::V6(addr)) => {
            buffer.write_byte(ADDRESS_TYPE_IPV6);
            buffer.write_all(&addr.octets());
        }
        None => return Err(error::new_invalid("unsupported address")),
    }
    put_port(buffer, destination.port);
    Ok(())
}

/// `udpIPSerializer.ReadAddrPort`.
fn read_ip_addr_port(reader: &mut Buffer) -> io::Result<Socksaddr> {
    let mut family = [0u8; 1];
    reader.read_full(&mut family)?;
    let addr = match family[0] {
        ADDRESS_TYPE_IPV4 => {
            let mut octets = [0u8; 4];
            reader.read_full(&mut octets).map_err(|err| error::cause(err, "read ipv4 address"))?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        ADDRESS_TYPE_IPV6 => {
            let mut octets = [0u8; 16];
            reader.read_full(&mut octets).map_err(|err| error::cause(err, "read ipv6 address"))?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        family => return Err(error::new_error(format!("unknown address family: {family}"))),
    };
    let mut port = [0u8; 2];
    reader.read_full(&mut port).map_err(|err| error::cause(err, "read port"))?;
    Ok(Socksaddr::from_ip(addr, u16::from_be_bytes(port)).unwrap())
}

pub fn write_udp_request_address(buffer: &mut Buffer, destination: &Socksaddr) -> io::Result<()> {
    // Surge 6.7.0 (11520): SGUDPConnectorSnellV4::sendData:toHostname:port:metadata: writes 0x00 before literal IP UDP targets.
    if destination.is_ip() {
        buffer.write_byte(0x00);
        return write_ip_addr_port(buffer, &destination.unwrap());
    }
    let host = destination.host_bytes();
    if host.is_empty() || host.len() > 255 {
        return Err(error::new_invalid("snell: invalid udp host"));
    }
    buffer.write_byte(host.len() as u8);
    buffer.write_all(&host);
    put_port(buffer, destination.port);
    Ok(())
}

pub fn read_udp_request_address(buffer: &mut Buffer) -> io::Result<Socksaddr> {
    let first = buffer.read_byte()?;
    if first != 0x00 {
        let host = buffer.read_bytes(first as usize)?.to_vec();
        let port = buffer.read_bytes(2)?;
        let port = u16::from_be_bytes([port[0], port[1]]);
        return Ok(Socksaddr::from_host_bytes(&host, port));
    }
    read_ip_addr_port(buffer)
}

/// snell-server v6.0.0b4: FUN_001431c0: UDP response sources are emitted as literal IPs only.
pub fn write_udp_response_address(buffer: &mut Buffer, source: &Socksaddr) -> io::Result<()> {
    let source = source.unwrap();
    if !source.is_ip() {
        return Err(error::new_invalid(format!("snell: udp response source is not an ip: {source}")));
    }
    write_ip_addr_port(buffer, &source)
}

pub fn read_udp_response_address(buffer: &mut Buffer) -> io::Result<Socksaddr> {
    read_ip_addr_port(buffer)
}

pub(crate) const MAX_UDP_REQUEST_HEADER_LEN: usize = 1 + 1 + 255 + 2;
pub(crate) const MAX_UDP_RESPONSE_HEADER_LEN: usize = 1 + 16 + 2;

/// Prepends the UDP forward command and the destination to a client packet.
pub(crate) fn write_udp_request_header(buffer: &mut Buffer, destination: &Socksaddr) -> io::Result<()> {
    let mut header = Buffer::with_capacity(MAX_UDP_REQUEST_HEADER_LEN + 1);
    header.write_byte(UDP_COMMAND_FORWARD);
    write_udp_request_address(&mut header, destination)?;
    buffer.extend_header(header.len()).copy_from_slice(header.bytes());
    Ok(())
}

/// Prepends the source address to a server packet.
pub(crate) fn write_udp_response_header(buffer: &mut Buffer, source: &Socksaddr) -> io::Result<()> {
    let mut header = Buffer::with_capacity(MAX_UDP_RESPONSE_HEADER_LEN);
    write_udp_response_address(&mut header, source)?;
    buffer.extend_header(header.len()).copy_from_slice(header.bytes());
    Ok(())
}

/// Reads the UDP forward command byte of a client packet record.
pub(crate) fn read_udp_command(record: &mut Buffer) -> io::Result<()> {
    let command = record.read_byte()?;
    if command != UDP_COMMAND_FORWARD {
        return Err(error::extend_code(ErrorCode::UnsupportedCommand, format!("udp {command}")));
    }
    Ok(())
}
