use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;

use super::FRAME_PAYLOAD_STEP;
use super::server::{ServiceInner, new_response_writer};
use crate::addr::Socksaddr;
use crate::address::{MAX_UDP_RESPONSE_HEADER_LEN, read_udp_command, write_udp_response_header};
use crate::buf::Buffer;
use crate::error::{self, ErrorCode};
use crate::net::{Conn, PacketConn, ReadWaitOptions};
use crate::reuse::{RecordReader, RecordWriter};
use crate::{ADDRESS_TYPE_IPV4, ADDRESS_TYPE_IPV6, AEAD_TAG_LEN, HEADER_CIPHER_LEN, MAX_PAYLOAD_LEN, REPLY_TUNNEL};

const MIN_UDP_PAYLOAD_LIMIT: usize = FRAME_PAYLOAD_STEP;

fn read_port(record: &mut Buffer) -> io::Result<u16> {
    let port = record.read_bytes(2)?;
    Ok(u16::from_be_bytes([port[0], port[1]]))
}

fn read_request_packet_destination(record: &mut Buffer) -> io::Result<Socksaddr> {
    let first = record.read_byte()?;
    if first != 0x00 {
        let host = String::from_utf8_lossy(record.read_bytes(first as usize)?).into_owned();
        let port = read_port(record)?;
        return Ok(Socksaddr::parse_host_port(&host, port));
    }
    let address_family = record.read_byte()?;
    match address_family {
        ADDRESS_TYPE_IPV4 => {
            let mut address = [0u8; 4];
            address.copy_from_slice(record.read_bytes(4)?);
            let port = read_port(record)?;
            Ok(Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::from(address)), port))
        }
        ADDRESS_TYPE_IPV6 => {
            let mut address = [0u8; 16];
            address.copy_from_slice(record.read_bytes(16)?);
            let port = read_port(record)?;
            Ok(Socksaddr::from_ip(IpAddr::V6(Ipv6Addr::from(address)), port).unwrap())
        }
        // snell-server v5.0.1: FUN_00140a50 consumes the 0x00 marker and the
        // unknown address-family byte, then forwards the rest as payload with an
        // empty destination instead of aborting the UDP tunnel.
        _ => Ok(Socksaddr::default()),
    }
}

pub(crate) struct ServerPacketConn {
    conn: Arc<dyn Conn>,
    service: Arc<ServiceInner>,
    reader: Arc<dyn RecordReader>,

    write_access: tokio::sync::Mutex<()>,
    writer: Mutex<Option<Arc<dyn RecordWriter>>>,
}

impl ServerPacketConn {
    pub(crate) fn new(
        conn: Arc<dyn Conn>,
        service: Arc<ServiceInner>,
        reader: Arc<dyn RecordReader>,
        writer: Option<Arc<dyn RecordWriter>>,
    ) -> Self {
        ServerPacketConn {
            conn,
            service,
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
        let (salt, record_writer) = new_response_writer(&self.service.psk, &self.conn)?;
        record_writer.write_first(&salt, &reply).await.map_err(|err| error::cause(err, "write udp reply"))?;
        *self.writer.lock().unwrap() = Some(Arc::new(record_writer));
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
        let destination = read_request_packet_destination(&mut record)?;
        if record.len() > buffer.free_len() {
            return Err(error::short_buffer());
        }
        buffer.write(record.bytes());
        Ok(destination)
    }

    async fn write_packet(&self, mut buffer: Buffer, destination: Socksaddr) -> io::Result<()> {
        let record_writer = self.ensure_writer().await?;
        write_udp_response_header(&mut buffer, &destination)?;
        if buffer.len() > MAX_PAYLOAD_LEN {
            return Err(ErrorCode::PayloadTooLarge.into());
        }
        record_writer.write_packet_buffer(buffer).await
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
        let destination = read_request_packet_destination(&mut record)?;
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
        let record_writer = self.ensure_writer().await?;
        for (buffer, destination) in buffers.iter_mut().zip(&destinations) {
            write_udp_response_header(buffer, destination)?;
        }
        record_writer.write_packet_vectorised(buffers).await
    }

    fn front_headroom(&self) -> usize {
        HEADER_CIPHER_LEN + MAX_UDP_RESPONSE_HEADER_LEN
    }

    fn rear_headroom(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn writer_mtu(&self) -> usize {
        MIN_UDP_PAYLOAD_LIMIT - MAX_UDP_RESPONSE_HEADER_LEN
    }
}
