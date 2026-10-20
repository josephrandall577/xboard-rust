use std::io;

use crate::addr::Socksaddr;
use crate::address::{read_connect_address, read_sock_string, write_connect_address};
use crate::buf::Buffer;
use crate::error::{self, ErrorCode};
use crate::{COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_PING, COMMAND_UDP, REQUEST_VERSION};

/// A snell request header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub command: u8,
    pub client_id: Vec<u8>,
    pub destination: Socksaddr,
}

impl Request {
    pub fn write(&self, buffer: &mut Buffer) -> io::Result<()> {
        if self.client_id.len() > 255 {
            return Err(error::new_invalid("snell: client id too long"));
        }
        buffer.write_all(&[REQUEST_VERSION, self.command, self.client_id.len() as u8]);
        if !self.client_id.is_empty() {
            buffer.write_all(&self.client_id);
        }
        match self.command {
            COMMAND_CONNECT | COMMAND_CONNECT_V2 => write_connect_address(buffer, &self.destination),
            COMMAND_PING | COMMAND_UDP => Ok(()),
            command => Err(error::extend_code(ErrorCode::UnsupportedCommand, command)),
        }
    }

    /// Encodes the request into a new vector.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut buffer = Buffer::with_capacity(self.len());
        self.write(&mut buffer)?;
        Ok(buffer.into_vec())
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        let request_len = 3 + self.client_id.len();
        match self.command {
            COMMAND_CONNECT | COMMAND_CONNECT_V2 => request_len + 1 + self.destination.host_bytes().len() + 2,
            _ => request_len,
        }
    }
}

/// `snell.ReadRequest`.
pub fn read_request(reader: &mut Buffer) -> io::Result<Request> {
    let mut prefix = [0u8; 3];
    reader.read_full(&mut prefix)?;
    if prefix[0] != REQUEST_VERSION {
        return Err(error::extend_code(ErrorCode::BadVersion, format!("request version {}", prefix[0])));
    }
    let client_id_len = prefix[2] as usize;
    let mut request = Request { command: prefix[1], ..Default::default() };
    if client_id_len > 0 {
        request.client_id = vec![0u8; client_id_len];
        reader.read_full(&mut request.client_id)?;
    }
    match request.command {
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
            request.destination = read_connect_address(reader)?;
        }
        COMMAND_PING | COMMAND_UDP => {}
        command => return Err(error::extend_code(ErrorCode::UnsupportedCommand, command)),
    }
    Ok(request)
}

/// Decodes a server error reply body into an error.
pub fn read_server_error(record: &mut Buffer) -> io::Error {
    let error_code = match record.read_byte() {
        Ok(code) => code,
        Err(err) => return err,
    };
    let message = match read_sock_string(record) {
        Ok(message) => message,
        Err(err) => return err,
    };
    // Surge 6.7.0 (11520): SNConnectorV4::socket:didReadData: rejects server-error replies unless the frame is
    // exactly code, message length, and message bytes.
    if !record.is_empty() {
        return error::new_error("snell: server error reply has trailing data");
    }
    io::Error::new(io::ErrorKind::ConnectionRefused, format!("snell: server error {error_code}: {message}"))
}

/// The request parser shared by the v5 and v6 servers.
///
/// snell-server v5.0.1: FUN_0013f630 and snell-server v6.0.0b4: FUN_00141bc0 handle
/// SN_COMMAND_PING immediately after the version/command bytes and abort with PONG data,
/// without consuming client-id bytes.
pub(crate) fn read_server_request(record: &mut Buffer) -> io::Result<Request> {
    let mut prefix = [0u8; 3];
    record.read_full(&mut prefix)?;
    if prefix[0] != REQUEST_VERSION {
        return Err(error::extend_code(ErrorCode::BadVersion, format!("request version {}", prefix[0])));
    }
    let mut request = Request { command: prefix[1], ..Default::default() };
    if request.command == COMMAND_PING {
        return Ok(request);
    }
    let client_id_len = prefix[2] as usize;
    if client_id_len > 0 {
        request.client_id = vec![0u8; client_id_len];
        record.read_full(&mut request.client_id)?;
    }
    match request.command {
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
            request.destination = read_connect_address(record)?;
        }
        COMMAND_UDP => {}
        command => return Err(error::extend_code(ErrorCode::UnsupportedCommand, command)),
    }
    Ok(request)
}
