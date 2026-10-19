use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

use super::packet::ServerPacketConn;
use super::server::{ServiceInner, error_reply, new_response_writer};
use super::{MAX_INITIAL_PADDING_LEN, MAX_PAYLOAD};
use crate::addr::Socksaddr;
use crate::buf::Buffer;
use crate::error::{self, ErrorCode, SharedResult};
use crate::net::{CloseHandler, Conn, Context, ReadWaitOptions};
use crate::request::{Request, read_server_request};
use crate::reuse::{
    REMOTE_EOF_CODE, REMOTE_EOF_MESSAGE, RecordReader, RecordWriter, WAITING_DISCARD_LIMIT, eof_to_none, eof_to_zero,
};
use crate::{
    AEAD_TAG_LEN, COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_PING, COMMAND_UDP, HEADER_CIPHER_LEN, REPLY_PONG,
    REPLY_TUNNEL, SALT_LEN,
};

pub(crate) struct ServerReuseSession {
    conn: Arc<dyn Conn>,
    service: Arc<ServiceInner>,
    reader: Arc<dyn RecordReader>,
    writer: Mutex<Option<Arc<dyn RecordWriter>>>,
}

impl ServerReuseSession {
    pub(crate) fn new(conn: Arc<dyn Conn>, service: Arc<ServiceInner>, reader: Arc<dyn RecordReader>) -> Self {
        ServerReuseSession { conn, service, reader, writer: Mutex::new(None) }
    }

    fn writer(&self) -> Option<Arc<dyn RecordWriter>> {
        self.writer.lock().unwrap().clone()
    }

    fn set_writer(&self, writer: Arc<dyn RecordWriter>) {
        *self.writer.lock().unwrap() = Some(writer);
    }

    async fn close_conn(&self) {
        let _ = self.conn.close().await;
    }

    pub(crate) async fn serve(
        self: &Arc<Self>,
        ctx: Context,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
        record: Buffer,
        request: Request,
    ) -> io::Result<()> {
        let mut on_close = on_close;
        let result = self.serve_loop(ctx, source, &mut on_close, record, request).await;
        if let Some(on_close) = on_close {
            return match result {
                Ok(()) => {
                    on_close(None);
                    Ok(())
                }
                Err(err) => {
                    let (reported, returned) = error::duplicate(err);
                    on_close(Some(reported));
                    Err(returned)
                }
            };
        }
        result
    }

    async fn serve_loop(
        self: &Arc<Self>,
        ctx: Context,
        source: Socksaddr,
        on_close: &mut Option<CloseHandler>,
        mut record: Buffer,
        mut request: Request,
    ) -> io::Result<()> {
        loop {
            let mut request_ctx = ctx.clone();
            match request.command {
                COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
                    if let Some(result) = self.service.authenticate(&ctx, &request) {
                        match result {
                            Ok(authenticated) => request_ctx = authenticated,
                            Err(err) => {
                                self.close_conn().await;
                                return Err(err);
                            }
                        }
                    }
                }
                COMMAND_UDP => {
                    if let Some(result) = self.service.authenticate(&ctx, &request) {
                        match result {
                            Ok(authenticated) => request_ctx = authenticated,
                            Err(err) => {
                                self.close_conn().await;
                                return Err(err);
                            }
                        }
                    }
                    let packet_conn = Arc::new(ServerPacketConn::new(
                        self.conn.clone(),
                        self.service.clone(),
                        self.reader.clone(),
                        self.writer(),
                    ));
                    if let Err(err) =
                        self.service.new_packet_connection(request_ctx, packet_conn.clone(), source, on_close).await
                    {
                        self.close_conn().await;
                        return Err(err);
                    }
                    if let Some(writer) = packet_conn.writer() {
                        self.set_writer(writer);
                    }
                    return Ok(());
                }
                COMMAND_PING => {
                    let result = match self.writer() {
                        None => self.service.write_pong(&self.conn).await,
                        Some(writer) => writer.write(&[REPLY_PONG]).await.map(|_| ()),
                    };
                    self.close_conn().await;
                    return result;
                }
                command => {
                    self.close_conn().await;
                    return Err(error::extend_code(ErrorCode::UnsupportedCommand, command));
                }
            }
            let server_conn = Arc::new(ServerReuseConn::new(self.clone()));
            if !record.is_empty() {
                self.reader.set_cache(Some(record));
            }
            let completion = server_conn.completion.clone();
            self.service.handler.new_connection(
                request_ctx.clone(),
                server_conn.clone(),
                source.clone(),
                request.destination.clone(),
                Some(Box::new(move |_| completion.cancel())),
            );
            tokio::select! {
                _ = server_conn.completion.cancelled() => {}
                _ = request_ctx.done() => {
                    self.close_conn().await;
                    return Err(error::canceled());
                }
            }
            if let Err(err) = server_conn.close_write().await {
                self.close_conn().await;
                return Err(err);
            }
            if server_conn.aborted.load(Ordering::SeqCst) {
                return Ok(());
            }
            if !server_conn.read_closed.load(Ordering::SeqCst) {
                // snell-server v5.0.1: after writing the EOF packet, FUN_0013f630 keeps
                // consuming client records (forwarding them into the still writable
                // outgoing socket) until the zero chunk reaches FUN_0013f500 ->
                // FUN_0013ddb0 -> FUN_0013dca0, which resets the tunnel stage so the
                // next record is parsed as a request. The handler has already released
                // the upstream, so discard instead, capped like the client waiting state.
                let mut discarded = 0;
                let drain_err = loop {
                    match self.reader.next_record().await {
                        Err(err) => break err,
                        Ok(drain_record) => {
                            discarded += drain_record.len();
                            if discarded >= WAITING_DISCARD_LIMIT {
                                self.close_conn().await;
                                return Err(error::new_error("snell: read too much data after request end"));
                            }
                        }
                    }
                };
                if !error::is_eof(&drain_err) {
                    self.close_conn().await;
                    return Err(error::cause(drain_err, "drain request"));
                }
            }
            record = match self.reader.read_record().await {
                Ok(record) => record,
                Err(err) if error::is_eof(&err) => return Ok(()),
                Err(err) => {
                    self.close_conn().await;
                    return Err(error::cause(err, "read request"));
                }
            };
            request = match read_server_request(&mut record) {
                Ok(request) => request,
                Err(err) => {
                    self.close_conn().await;
                    return Err(error::cause(err, "decode request"));
                }
            };
        }
    }
}

#[derive(Default)]
struct WriteState {
    reply_written: bool,
    write_closed: bool,
}

pub(crate) struct ServerReuseConn {
    session: Arc<ServerReuseSession>,

    access: tokio::sync::Mutex<WriteState>,
    reply_written: AtomicBool,
    close_write: OnceCell<SharedResult>,
    close: OnceCell<SharedResult>,
    read_closed: AtomicBool,
    aborted: AtomicBool,
    completion: CancellationToken,
}

impl ServerReuseConn {
    fn new(session: Arc<ServerReuseSession>) -> Self {
        ServerReuseConn {
            session,
            access: tokio::sync::Mutex::new(WriteState::default()),
            reply_written: AtomicBool::new(false),
            close_write: OnceCell::new(),
            close: OnceCell::new(),
            read_closed: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
            completion: CancellationToken::new(),
        }
    }

    fn mark_reply_written(&self, state: &mut WriteState) {
        state.reply_written = true;
        self.reply_written.store(true, Ordering::SeqCst);
    }

    async fn write_first_response(&self, reply: &[u8], context: &str) -> io::Result<()> {
        let session = &self.session;
        let (salt, writer) = new_response_writer(&session.service.psk, &session.conn)?;
        writer.write_first(&salt, reply).await.map_err(|err| error::cause(err, context.to_string()))?;
        session.set_writer(Arc::new(writer));
        Ok(())
    }

    async fn write_response(&self, state: &mut WriteState, payload: &[u8]) -> io::Result<()> {
        let mut reply = Vec::with_capacity(1 + payload.len());
        reply.push(REPLY_TUNNEL);
        reply.extend_from_slice(payload);
        match self.session.writer() {
            None => self.write_first_response(&reply, "write reply").await?,
            Some(writer) => {
                writer.write(&reply).await.map_err(|err| error::cause(err, "write reply"))?;
            }
        }
        self.mark_reply_written(state);
        Ok(())
    }

    async fn write_response_buffer(&self, state: &mut WriteState, mut buffer: Buffer) -> io::Result<()> {
        buffer.extend_header(1)[0] = REPLY_TUNNEL;
        match self.session.writer() {
            Some(writer) => writer.write_buffer(buffer).await.map_err(|err| error::cause(err, "write reply"))?,
            None => self.write_first_response(buffer.bytes(), "write reply").await?,
        }
        self.mark_reply_written(state);
        Ok(())
    }

    async fn write_error_response(&self, code: u8, message: &str) -> io::Result<()> {
        let reply = error_reply(code, message);
        match self.session.writer() {
            None => self.write_first_response(&reply, "write error reply").await,
            Some(writer) => {
                writer.write(&reply).await.map(|_| ()).map_err(|err| error::cause(err, "write error reply"))
            }
        }
    }

    fn finish_read<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Err(err) = &result
            && error::is_eof(err)
        {
            self.read_closed.store(true, Ordering::SeqCst);
        }
        result
    }
}

#[async_trait]
impl Conn for ServerReuseConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        eof_to_zero(self.finish_read(self.session.reader.read(buf).await))
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.access.lock().await;
        if state.write_closed {
            return Err(error::closed());
        }
        if state.reply_written {
            return self.session.writer().unwrap().write(buf).await;
        }
        self.write_response(&mut state, buf).await?;
        Ok(buf.len())
    }

    async fn close(&self) -> io::Result<()> {
        // The handler may close this side while its peer copy is still reading.
        // on_close owns completion and runs only after both copy directions exit.
        self.close.get_or_init(|| async { SharedResult::new(self.close_write().await) }).await.get()
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.session.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.session.conn.set_write_deadline(deadline)
    }

    fn local_addr(&self) -> Socksaddr {
        self.session.conn.local_addr()
    }

    fn remote_addr(&self) -> Socksaddr {
        self.session.conn.remote_addr()
    }

    async fn close_write(&self) -> io::Result<()> {
        self.close_write
            .get_or_init(|| async {
                let mut state = self.access.lock().await;
                state.write_closed = true;
                // snell-server v5.0.1: FUN_0013f020 reports upstream EOF before any
                // payload as ReplyError 0x65 "Remote EOF", then aborts the reusable tunnel.
                if !state.reply_written {
                    let mut result = self.write_error_response(REMOTE_EOF_CODE, REMOTE_EOF_MESSAGE).await;
                    if result.is_ok() {
                        self.aborted.store(true, Ordering::SeqCst);
                        result = self.session.conn.close().await;
                    }
                    return SharedResult::new(result);
                }
                SharedResult::new(self.session.writer().unwrap().write_zero_chunk().await)
            })
            .await
            .get()
    }

    async fn read_buffer(&self, buffer: &mut Buffer) -> io::Result<usize> {
        if buffer.free_len() == 0 {
            return Err(error::short_buffer());
        }
        eof_to_zero(self.finish_read(self.session.reader.read_buffer(buffer).await))
    }

    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let mut state = self.access.lock().await;
        if state.write_closed {
            return Err(error::closed());
        }
        if state.reply_written {
            return self.session.writer().unwrap().write_buffer(buffer).await;
        }
        self.write_response_buffer(&mut state, buffer).await
    }

    fn supports_vectorised(&self) -> bool {
        self.session.conn.supports_vectorised()
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        if !self.session.conn.supports_vectorised() {
            for buffer in buffers {
                self.write_buffer(buffer).await?;
            }
            return Ok(());
        }
        let mut state = self.access.lock().await;
        if state.write_closed {
            return Err(error::closed());
        }
        if state.reply_written {
            return self.session.writer().unwrap().write_vectorised(buffers).await;
        }
        let mut buffers = buffers.into_iter();
        while let Some(buffer) = buffers.next() {
            if buffer.is_empty() {
                continue;
            }
            self.write_response_buffer(&mut state, buffer).await?;
            let rest: Vec<Buffer> = buffers.collect();
            if !rest.is_empty() {
                return self.session.writer().unwrap().write_vectorised(rest).await;
            }
            return Ok(());
        }
        Ok(())
    }

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        self.session.reader.initialize_read_waiter(options)
    }

    async fn wait_read_buffer(&self) -> io::Result<Option<Buffer>> {
        eof_to_none(self.finish_read(self.session.reader.wait_read_buffer().await))
    }

    fn front_headroom(&self) -> usize {
        if self.reply_written.load(Ordering::SeqCst) {
            return HEADER_CIPHER_LEN;
        }
        if self.session.writer().is_some() {
            return 1 + HEADER_CIPHER_LEN;
        }
        1 + SALT_LEN + HEADER_CIPHER_LEN + MAX_INITIAL_PADDING_LEN
    }

    fn rear_headroom(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn writer_mtu(&self) -> usize {
        MAX_PAYLOAD
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use tokio::sync::Notify;

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum OrderedWrite {
        Payload(Vec<u8>),
        Eof,
    }

    struct OrderedRecordWriter {
        writes: StdMutex<Vec<OrderedWrite>>,
        second_buffer_pending: Notify,
        allow_second_buffer: Notify,
    }

    #[async_trait]
    impl RecordWriter for OrderedRecordWriter {
        async fn write(&self, _: &[u8]) -> io::Result<usize> {
            unreachable!()
        }

        async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
            self.writes.lock().unwrap().push(OrderedWrite::Payload(buffer.bytes()[1..].to_vec()));
            Ok(())
        }

        async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
            self.second_buffer_pending.notify_one();
            self.allow_second_buffer.notified().await;
            for buffer in buffers {
                self.writes.lock().unwrap().push(OrderedWrite::Payload(buffer.bytes().to_vec()));
            }
            Ok(())
        }

        async fn write_packet_vectorised(&self, _: Vec<Buffer>) -> io::Result<()> {
            unreachable!()
        }

        async fn write_packet_buffer(&self, _: Buffer) -> io::Result<()> {
            unreachable!()
        }

        async fn write_zero_chunk(&self) -> io::Result<()> {
            self.writes.lock().unwrap().push(OrderedWrite::Eof);
            Ok(())
        }

        fn front_headroom(&self) -> usize {
            0
        }

        fn rear_headroom(&self) -> usize {
            0
        }

        fn writer_mtu(&self) -> usize {
            0
        }
    }

    /// A transport that only claims vectorised support.
    struct VectorisedConn;

    #[async_trait]
    impl Conn for VectorisedConn {
        async fn read(&self, _: &mut [u8]) -> io::Result<usize> {
            unreachable!()
        }

        async fn write(&self, _: &[u8]) -> io::Result<usize> {
            unreachable!()
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }

        fn set_read_deadline(&self, _: Option<Instant>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_deadline(&self, _: Option<Instant>) -> io::Result<()> {
            Ok(())
        }

        fn supports_vectorised(&self) -> bool {
            true
        }
    }

    struct NoopHandler;

    impl crate::net::Handler for NoopHandler {
        fn new_connection(&self, _: Context, _: Arc<dyn Conn>, _: Socksaddr, _: Socksaddr, _: Option<CloseHandler>) {}

        fn new_packet_connection(
            &self,
            _: Context,
            _: Arc<dyn crate::net::PacketConn>,
            _: Socksaddr,
            _: Socksaddr,
            _: Option<CloseHandler>,
        ) {
        }
    }

    struct NoopReader;

    #[async_trait]
    impl RecordReader for NoopReader {
        async fn read_record(&self) -> io::Result<Buffer> {
            unreachable!()
        }

        async fn next_record(&self) -> io::Result<Buffer> {
            unreachable!()
        }

        fn set_cache(&self, _: Option<Buffer>) {}

        async fn read(&self, _: &mut [u8]) -> io::Result<usize> {
            unreachable!()
        }

        async fn read_buffer(&self, _: &mut Buffer) -> io::Result<usize> {
            unreachable!()
        }

        fn initialize_read_waiter(&self, _: ReadWaitOptions) -> bool {
            false
        }

        async fn wait_read_buffer(&self) -> io::Result<Buffer> {
            unreachable!()
        }
    }

    fn new_server_write_buffer(payload: &[u8]) -> Buffer {
        let mut buffer = Buffer::with_capacity(1 + payload.len());
        buffer.resize(1, 0);
        buffer.write(payload);
        buffer
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_reuse_vectorised_response_completes_before_close_write() {
        let part_a = b"first-vector-buffer".to_vec();
        let part_b = b"second-vector-buffer".to_vec();
        let record_writer = Arc::new(OrderedRecordWriter {
            writes: StdMutex::new(Vec::new()),
            second_buffer_pending: Notify::new(),
            allow_second_buffer: Notify::new(),
        });
        let service = super::super::server::test_service_inner(Arc::new(NoopHandler));
        let session = Arc::new(ServerReuseSession::new(Arc::new(VectorisedConn), service, Arc::new(NoopReader)));
        session.set_writer(record_writer.clone());
        let conn = Arc::new(ServerReuseConn::new(session));

        let write_task = {
            let conn = conn.clone();
            let buffers = vec![new_server_write_buffer(&part_a), new_server_write_buffer(&part_b)];
            tokio::spawn(async move { conn.write_vectorised(buffers).await })
        };
        record_writer.second_buffer_pending.notified().await;

        let close_task = {
            let conn = conn.clone();
            tokio::spawn(async move { conn.close_write().await })
        };
        // With one thread, yield until CloseWrite either completes (old behavior) or
        // blocks behind the vectorised response lock (fixed behavior).
        tokio::task::yield_now().await;
        record_writer.allow_second_buffer.notify_one();
        write_task.await.unwrap().expect("write vectorised");
        close_task.await.unwrap().expect("close write");

        assert_eq!(
            *record_writer.writes.lock().unwrap(),
            vec![OrderedWrite::Payload(part_a), OrderedWrite::Payload(part_b), OrderedWrite::Eof]
        );
    }
}
