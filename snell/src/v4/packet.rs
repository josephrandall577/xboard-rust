use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use async_trait::async_trait;

use super::client::ClientConfig;
use super::{FRAME_SIZE, RESET_RECORD_OVERHEAD, Reader, Writer, new_reader};
use crate::addr::Socksaddr;
use crate::address::{MAX_UDP_REQUEST_HEADER_LEN, write_udp_request_header};
use crate::buf::Buffer;
use crate::error::{self, ErrorCode};
use crate::net::{Conn, PacketConn, ReadWaitOptions};
use crate::request::Request;
use crate::reuse::{RecordReader, RecordWriter, parse_reply};
use crate::{
    ADDRESS_TYPE_IPV4, ADDRESS_TYPE_IPV6, AEAD_TAG_LEN, COMMAND_UDP, HEADER_CIPHER_LEN, MAX_PAYLOAD_LEN,
    read_udp_response_address,
};

const MIN_UDP_PAYLOAD_LIMIT: usize = FRAME_SIZE - RESET_RECORD_OVERHEAD;

/// A UDP-over-TCP client connection.
pub struct ClientPacketConn {
    conn: Arc<dyn Conn>,
    config: Arc<ClientConfig>,

    write_access: tokio::sync::Mutex<()>,
    writer: OnceLock<Arc<Writer>>,

    read_access: tokio::sync::Mutex<()>,
    reader: OnceLock<Arc<Reader>>,
    read_wait_options: Mutex<ReadWaitOptions>,
}

impl ClientPacketConn {
    pub(crate) fn new(conn: Arc<dyn Conn>, config: Arc<ClientConfig>) -> Self {
        ClientPacketConn {
            conn,
            config,
            write_access: tokio::sync::Mutex::new(()),
            writer: OnceLock::new(),
            read_access: tokio::sync::Mutex::new(()),
            reader: OnceLock::new(),
            read_wait_options: Mutex::new(ReadWaitOptions::default()),
        }
    }

    async fn write_request(&self) -> io::Result<&Arc<Writer>> {
        let _guard = self.write_access.lock().await;
        if let Some(writer) = self.writer.get() {
            return Ok(writer);
        }
        let record_writer = Writer::new(self.conn.clone(), self.config.psk.clone());
        let request = Request { command: COMMAND_UDP, client_id: self.config.user_key.clone(), ..Default::default() };
        let request = request.encode()?;
        record_writer.write(&request).await.map_err(|err| error::cause(err, "write udp request"))?;
        Ok(self.writer.get_or_init(|| Arc::new(record_writer)))
    }

    async fn read_reply(&self) -> io::Result<&Arc<Reader>> {
        let _guard = self.read_access.lock().await;
        if let Some(reader) = self.reader.get() {
            return Ok(reader);
        }
        let record_reader = new_reader(self.conn.clone(), self.config.psk.clone());
        record_reader.initialize_read_waiter(*self.read_wait_options.lock().unwrap());
        let record = record_reader.read_record().await.map_err(|err| error::cause(err, "read udp reply"))?;
        let cached = parse_reply(record)?;
        if cached.is_some() {
            record_reader.set_cache(cached);
        }
        Ok(self.reader.get_or_init(|| Arc::new(record_reader)))
    }

    async fn handshake(&self) -> io::Result<&Arc<Writer>> {
        let writer = self.write_request().await?;
        self.read_reply().await?;
        Ok(writer)
    }
}

/// Skips UDP response frames whose address type is neither IPv4 nor IPv6.
///
/// Surge 6.7.0 (11520): SGUDPConnectorSnellV4::socket:didReadData: silently ignores UDP
/// response frames whose address type is neither IPv4 nor IPv6.
fn check_response(record: &Buffer) -> io::Result<bool> {
    if record.len() < 8 {
        return Err(error::new_error("snell: udp response too short"));
    }
    let address_type = record.bytes()[0];
    Ok(address_type == ADDRESS_TYPE_IPV4 || address_type == ADDRESS_TYPE_IPV6)
}

#[async_trait]
impl PacketConn for ClientPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let reader = self.read_reply().await?;
        loop {
            let mut record = reader.next_record().await?;
            if !check_response(&record)? {
                continue;
            }
            let destination = read_udp_response_address(&mut record)?;
            if record.len() > buffer.free_len() {
                return Err(error::short_buffer());
            }
            buffer.write(record.bytes());
            return Ok(destination);
        }
    }

    async fn write_packet(&self, mut buffer: Buffer, destination: Socksaddr) -> io::Result<()> {
        let writer = self.handshake().await?;
        write_udp_request_header(&mut buffer, &destination)?;
        if buffer.len() > MAX_PAYLOAD_LEN {
            return Err(ErrorCode::PayloadTooLarge.into());
        }
        writer.write_packet_buffer(buffer).await
    }

    async fn close(&self) -> io::Result<()> {
        self.conn.close().await
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.conn.set_write_deadline(deadline)
    }

    fn local_addr(&self) -> Socksaddr {
        self.conn.local_addr()
    }

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        *self.read_wait_options.lock().unwrap() = options;
        if let Some(reader) = self.reader.get() {
            reader.initialize_read_waiter(options);
        }
        false
    }

    async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
        let reader = self.read_reply().await?;
        loop {
            let mut record = reader.wait_read_buffer().await?;
            if !check_response(&record)? {
                continue;
            }
            let destination = read_udp_response_address(&mut record)?;
            return Ok((record, destination));
        }
    }

    fn supports_packet_batch(&self) -> bool {
        self.conn.supports_vectorised()
    }

    async fn write_packet_batch(&self, mut buffers: Vec<Buffer>, destinations: Vec<Socksaddr>) -> io::Result<()> {
        if buffers.is_empty() || buffers.len() != destinations.len() {
            return Err(error::invalid());
        }
        if !self.conn.supports_vectorised() {
            for (buffer, destination) in buffers.into_iter().zip(destinations) {
                self.write_packet(buffer, destination).await?;
            }
            return Ok(());
        }
        let writer = self.handshake().await?;
        for (buffer, destination) in buffers.iter_mut().zip(&destinations) {
            write_udp_request_header(buffer, destination)?;
        }
        writer.write_packet_vectorised(buffers).await
    }

    fn front_headroom(&self) -> usize {
        HEADER_CIPHER_LEN + MAX_UDP_REQUEST_HEADER_LEN
    }

    fn rear_headroom(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn writer_mtu(&self) -> usize {
        MIN_UDP_PAYLOAD_LIMIT - MAX_UDP_REQUEST_HEADER_LEN
    }
}
