use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use async_trait::async_trait;

use super::MAX_PAYLOAD;
use super::client::ClientConfig;
use super::handshake::Framing;
use crate::addr::Socksaddr;
use crate::address::{
    MAX_UDP_REQUEST_HEADER_LEN, MAX_UDP_RESPONSE_HEADER_LEN, read_udp_command, read_udp_request_address,
    read_udp_response_address, write_udp_request_header, write_udp_response_header,
};
use crate::buf::Buffer;
use crate::error::{self, ErrorCode};
use crate::net::{Conn, PacketConn, ReadWaitOptions};
use crate::request::Request;
use crate::reuse::{RecordReader, RecordWriter, parse_reply};
use crate::{COMMAND_UDP, REPLY_TUNNEL};

/// A UDP-over-TCP v6 client connection.
pub struct ClientPacketConn {
    conn: Arc<dyn Conn>,
    config: Arc<ClientConfig>,

    write_access: tokio::sync::Mutex<()>,
    writer: OnceLock<Arc<dyn RecordWriter>>,

    read_access: tokio::sync::Mutex<()>,
    reader: OnceLock<Arc<dyn RecordReader>>,
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

    async fn write_request(&self) -> io::Result<&Arc<dyn RecordWriter>> {
        let _guard = self.write_access.lock().await;
        if let Some(writer) = self.writer.get() {
            return Ok(writer);
        }
        let request = Request { command: COMMAND_UDP, client_id: self.config.user_key.clone(), ..Default::default() };
        let request = request.encode()?;
        let writer = self
            .config
            .framing
            .write_first_record(&self.conn, &request)
            .await
            .map_err(|err| error::cause(err, "write udp request"))?;
        Ok(self.writer.get_or_init(|| writer))
    }

    async fn read_reply(&self) -> io::Result<&Arc<dyn RecordReader>> {
        let _guard = self.read_access.lock().await;
        if let Some(reader) = self.reader.get() {
            return Ok(reader);
        }
        let options = *self.read_wait_options.lock().unwrap();
        let (reader, record) = self
            .config
            .framing
            .read_first_record(&self.conn, options)
            .await
            .map_err(|err| error::cause(err, "read udp reply"))?;
        let cached = parse_reply(record)?;
        reader.set_cache(cached);
        Ok(self.reader.get_or_init(|| reader))
    }

    async fn handshake(&self) -> io::Result<&Arc<dyn RecordWriter>> {
        let writer = self.write_request().await?;
        self.read_reply().await?;
        Ok(writer)
    }
}

#[async_trait]
impl PacketConn for ClientPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let reader = self.read_reply().await?;
        let mut record = reader.next_record().await?;
        let destination = read_udp_response_address(&mut record)?;
        if record.len() > buffer.free_len() {
            return Err(error::short_buffer());
        }
        buffer.write(record.bytes());
        Ok(destination)
    }

    async fn write_packet(&self, mut buffer: Buffer, destination: Socksaddr) -> io::Result<()> {
        let writer = self.handshake().await?;
        write_udp_request_header(&mut buffer, &destination)?;
        if buffer.len() > MAX_PAYLOAD {
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
        let mut record = reader.wait_read_buffer().await?;
        let destination = read_udp_response_address(&mut record)?;
        Ok((record, destination))
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
        self.config.framing.packet_front_headroom() + MAX_UDP_REQUEST_HEADER_LEN
    }

    fn rear_headroom(&self) -> usize {
        self.config.framing.rear_headroom()
    }

    fn writer_mtu(&self) -> usize {
        MAX_PAYLOAD - MAX_UDP_REQUEST_HEADER_LEN
    }
}

pub(crate) struct ServerPacketConn {
    conn: Arc<dyn Conn>,
    framing: Framing,
    reader: Arc<dyn RecordReader>,

    write_access: tokio::sync::Mutex<()>,
    writer: Mutex<Option<Arc<dyn RecordWriter>>>,
}

impl ServerPacketConn {
    pub(crate) fn new(
        conn: Arc<dyn Conn>,
        framing: Framing,
        reader: Arc<dyn RecordReader>,
        writer: Option<Arc<dyn RecordWriter>>,
    ) -> Self {
        ServerPacketConn {
            conn,
            framing,
            reader,
            write_access: tokio::sync::Mutex::new(()),
            writer: Mutex::new(writer),
        }
    }

    pub(crate) fn writer(&self) -> Option<Arc<dyn RecordWriter>> {
        self.writer.lock().unwrap().clone()
    }

    pub(crate) async fn write_tunnel_reply(&self) -> io::Result<()> {
        let reply = [REPLY_TUNNEL];
        if let Some(writer) = self.writer() {
            writer.write(&reply).await.map_err(|err| error::cause(err, "write udp reply"))?;
            return Ok(());
        }
        let writer = self
            .framing
            .write_first_record(&self.conn, &reply)
            .await
            .map_err(|err| error::cause(err, "write udp reply"))?;
        *self.writer.lock().unwrap() = Some(writer);
        Ok(())
    }

    async fn ensure_writer(&self) -> io::Result<Arc<dyn RecordWriter>> {
        let _guard = self.write_access.lock().await;
        if self.writer().is_none() {
            self.write_tunnel_reply().await?;
        }
        Ok(self.writer().unwrap())
    }
}

#[async_trait]
impl PacketConn for ServerPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let mut record = self.reader.next_record().await?;
        read_udp_command(&mut record)?;
        let destination = read_udp_request_address(&mut record)?;
        if record.len() > buffer.free_len() {
            return Err(error::short_buffer());
        }
        buffer.write(record.bytes());
        Ok(destination)
    }

    async fn write_packet(&self, mut buffer: Buffer, destination: Socksaddr) -> io::Result<()> {
        let writer = self.ensure_writer().await?;
        write_udp_response_header(&mut buffer, &destination)?;
        if buffer.len() > MAX_PAYLOAD {
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
        self.reader.initialize_read_waiter(options);
        false
    }

    async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
        let mut record = self.reader.wait_read_buffer().await?;
        read_udp_command(&mut record)?;
        let destination = read_udp_request_address(&mut record)?;
        Ok((record, destination))
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
        let writer = self.ensure_writer().await?;
        for (buffer, destination) in buffers.iter_mut().zip(&destinations) {
            write_udp_response_header(buffer, destination)?;
        }
        writer.write_packet_vectorised(buffers).await
    }

    fn front_headroom(&self) -> usize {
        self.framing.packet_front_headroom() + MAX_UDP_RESPONSE_HEADER_LEN
    }

    fn rear_headroom(&self) -> usize {
        self.framing.rear_headroom()
    }

    fn writer_mtu(&self) -> usize {
        MAX_PAYLOAD - MAX_UDP_RESPONSE_HEADER_LEN
    }
}
