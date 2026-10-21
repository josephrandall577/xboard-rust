//! A loopback throughput benchmark for the v6 tunnel.
//!
//! ```text
//! snell-bench server --listen 127.0.0.1:16160 --psk <psk> [--copy read|buffer]
//! snell-bench client --server 127.0.0.1:16160 --psk <psk> --dest discard|source \
//!     --seconds 5 [--streams 1] [--size 32768] [--copy read|buffer]
//! ```
//!
//! `dest=discard` measures client → server upload; the server reads and drops.
//! `dest=source` measures server → client download; the server writes a constant
//! stream. `--copy read` uses `Conn::read` / `Conn::write`, `--copy buffer` uses
//! `wait_read_buffer` / `write_buffer` (the zero-copy path).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use snell::{Buffer, CloseHandler, Conn, Context, Handler, PacketConn, ReadWaitOptions, Socksaddr, TcpConn, v6};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyMode {
    Read,
    Buffer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkMode {
    Discard,
    Source,
}

struct Options {
    role: String,
    listen: String,
    server: String,
    psk: Vec<u8>,
    mode: v6::Mode,
    dest: String,
    seconds: u64,
    streams: usize,
    size: usize,
    copy: CopyMode,
    workers: usize,
    sink_port: u16,
    sink_mode: SinkMode,
}

fn parse_args() -> io::Result<Options> {
    let mut options = Options {
        role: String::new(),
        listen: "127.0.0.1:16160".into(),
        server: "127.0.0.1:16160".into(),
        psk: b"benchmark-psk-012345".to_vec(),
        mode: v6::Mode::Default,
        dest: "discard".into(),
        seconds: 5,
        streams: 1,
        size: 32 * 1024,
        copy: CopyMode::Buffer,
        workers: 0,
        sink_port: 0,
        sink_mode: SinkMode::Discard,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| io::Error::other(format!("missing value for {arg}")));
        match arg.as_str() {
            "server" | "client" => options.role = arg,
            "--listen" => options.listen = value()?,
            "--server" => options.server = value()?,
            "--psk" => options.psk = value()?.into_bytes(),
            "--mode" => {
                options.mode = match value()?.as_str() {
                    "default" => v6::Mode::Default,
                    "unshaped" => v6::Mode::Unshaped,
                    "unsafe-raw" | "raw" => v6::Mode::UnsafeRaw,
                    other => return Err(io::Error::other(format!("unknown mode: {other}"))),
                }
            }
            "--dest" => options.dest = value()?,
            "--seconds" => options.seconds = value()?.parse().map_err(io::Error::other)?,
            "--streams" => options.streams = value()?.parse().map_err(io::Error::other)?,
            "--size" => options.size = value()?.parse().map_err(io::Error::other)?,
            "--workers" => options.workers = value()?.parse().map_err(io::Error::other)?,
            "--sink-port" => options.sink_port = value()?.parse().map_err(io::Error::other)?,
            "--sink-mode" => {
                options.sink_mode = match value()?.as_str() {
                    "discard" => SinkMode::Discard,
                    "source" => SinkMode::Source,
                    other => return Err(io::Error::other(format!("unknown sink mode: {other}"))),
                }
            }
            "--copy" => {
                options.copy = match value()?.as_str() {
                    "read" => CopyMode::Read,
                    "buffer" => CopyMode::Buffer,
                    other => return Err(io::Error::other(format!("unknown copy mode: {other}"))),
                }
            }
            "-h" | "--help" => {
                println!("usage: snell-bench server|client [options]");
                std::process::exit(0);
            }
            other => return Err(io::Error::other(format!("unknown argument: {other}"))),
        }
    }
    if options.role.is_empty() {
        return Err(io::Error::other("missing role: server or client"));
    }
    Ok(options)
}

struct BenchHandler {
    copy: CopyMode,
    sink_port: u16,
}

async fn relay_conn(tunnel: Arc<dyn Conn>, upstream: Arc<dyn Conn>, copy: CopyMode) -> io::Result<()> {
    async fn pipe(from: Arc<dyn Conn>, to: Arc<dyn Conn>, copy: CopyMode) -> io::Result<()> {
        match copy {
            CopyMode::Read => {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match from.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            to.write(&buf[..n]).await?;
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
            CopyMode::Buffer => {
                from.initialize_read_waiter(ReadWaitOptions {
                    front_headroom: to.front_headroom(),
                    rear_headroom: to.rear_headroom(),
                    mtu: to.writer_mtu(),
                    ..Default::default()
                });
                while let Some(buffer) = from.wait_read_buffer().await? {
                    to.write_buffer(buffer).await?;
                }
            }
        }
        let _ = to.close_write().await;
        Ok(())
    }
    let _ = tokio::join!(pipe(tunnel.clone(), upstream.clone(), copy), pipe(upstream.clone(), tunnel.clone(), copy));
    let _ = tunnel.close().await;
    let _ = upstream.close().await;
    Ok(())
}

async fn run_sink(listener: TcpListener, mode: SinkMode) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { return };
        match mode {
            SinkMode::Discard => {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match stream.try_read(&mut buf) {
                            Ok(0) => return,
                            Ok(_) => {}
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                            Err(_) => return,
                        }
                        if stream.readable().await.is_err() {
                            return;
                        }
                    }
                });
            }
            SinkMode::Source => {
                tokio::spawn(async move {
                    let data = vec![0x5au8; 64 * 1024];
                    loop {
                        match stream.try_write(&data) {
                            Ok(_) => {}
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                            Err(_) => return,
                        }
                        if stream.writable().await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
    }
}

impl Handler for BenchHandler {
    fn new_connection(
        &self,
        _: Context,
        conn: Arc<dyn Conn>,
        _: Socksaddr,
        destination: Socksaddr,
        _: Option<CloseHandler>,
    ) {
        let copy = self.copy;
        let sink_port = self.sink_port;
        if destination.fqdn.starts_with("relay") {
            tokio::spawn(async move {
                let sink_addr = format!("127.0.0.1:{sink_port}");
                if let Ok(stream) = TcpStream::connect(&sink_addr).await
                    && let Ok(upstream) = TcpConn::new(stream)
                {
                    let upstream: Arc<dyn Conn> = Arc::new(upstream);
                    let _ = relay_conn(conn.clone(), upstream, copy).await;
                }
                let _ = conn.close().await;
            });
            return;
        }
        let sink = if destination.fqdn == "source" { SinkMode::Source } else { SinkMode::Discard };
        tokio::spawn(async move {
            match sink {
                SinkMode::Discard => {
                    let mut total = 0u64;
                    match copy {
                        CopyMode::Read => {
                            let mut buf = vec![0u8; 64 * 1024];
                            loop {
                                match conn.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => total += n as u64,
                                }
                            }
                        }
                        CopyMode::Buffer => {
                            while let Ok(Some(buffer)) = conn.wait_read_buffer().await {
                                total += buffer.len() as u64;
                            }
                        }
                    }
                    eprintln!("server read {:.2} GiB", total as f64 / (1u64 << 30) as f64);
                }
                SinkMode::Source => {
                    let size = 32 * 1024;
                    let front = conn.front_headroom();
                    let rear = conn.rear_headroom();
                    let mut total = 0u64;
                    loop {
                        let mut buffer = Buffer::with_capacity(front + size + rear);
                        if front > 0 {
                            buffer.resize(front, 0);
                        }
                        buffer.extend(size).fill(0x5a);
                        match copy {
                            CopyMode::Read => {
                                if conn.write(buffer.bytes()).await.is_err() {
                                    break;
                                }
                            }
                            CopyMode::Buffer => {
                                if conn.write_buffer(buffer).await.is_err() {
                                    break;
                                }
                            }
                        }
                        total += size as u64;
                    }
                    eprintln!("server wrote {:.2} GiB", total as f64 / (1u64 << 30) as f64);
                }
            }
            let _ = conn.close().await;
        });
    }

    fn new_packet_connection(
        &self,
        _: Context,
        _: Arc<dyn PacketConn>,
        _: Socksaddr,
        _: Socksaddr,
        _: Option<CloseHandler>,
    ) {
    }
}

async fn run_server(options: Options) -> io::Result<()> {
    let sink_port = if options.sink_port != 0 {
        let listener = TcpListener::bind(("127.0.0.1", options.sink_port)).await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(run_sink(listener, options.sink_mode));
        port
    } else {
        0
    };
    let service = v6::Service::new(v6::ServerOptions {
        psk: options.psk,
        mode: options.mode,
        handler: Arc::new(BenchHandler { copy: options.copy, sink_port }),
    })?;
    let listener = TcpListener::bind(&options.listen).await?;
    eprintln!("listening on {}", listener.local_addr()?);
    loop {
        let (stream, addr) = listener.accept().await?;
        let service = service.clone();
        tokio::spawn(async move {
            let Ok(conn) = TcpConn::new(stream) else { return };
            let conn: Arc<dyn Conn> = Arc::new(conn);
            if let Err(err) = service.new_connection(Context::new(), conn.clone(), Socksaddr::from(addr), None).await {
                let _ = err.conn.close().await;
            }
        });
    }
}

async fn run_client(options: Options) -> io::Result<()> {
    let client = v6::Client::new(v6::ClientOptions {
        psk: options.psk.clone(),
        mode: options.mode,
        server: Socksaddr::parse(&options.server),
        ..Default::default()
    })?;
    let destination = Socksaddr::parse(&format!("{}:1", options.dest));
    let upload = options.dest == "discard" || options.dest.ends_with("up");
    let counter = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(options.seconds);
    let mut tasks = Vec::new();
    for _ in 0..options.streams {
        let client = client.clone();
        let destination = destination.clone();
        let counter = counter.clone();
        let copy = options.copy;
        let size = options.size;
        let server = options.server.clone();
        tasks.push(tokio::spawn(async move {
            let stream = TcpStream::connect(&server).await?;
            let conn = client.dial_conn(Arc::new(TcpConn::new(stream)?), destination).await?;
            let total = if upload {
                let front = conn.front_headroom();
                let rear = conn.rear_headroom();
                let mut total = 0u64;
                let mut buffer = vec![0u8; size];
                buffer.fill(0x5a);
                loop {
                    if Instant::now() >= deadline {
                        break;
                    }
                    match copy {
                        CopyMode::Read => {
                            if conn.write(&buffer).await.is_err() {
                                break;
                            }
                        }
                        CopyMode::Buffer => {
                            let mut b = Buffer::with_capacity(front + size + rear);
                            if front > 0 {
                                b.resize(front, 0);
                            }
                            b.extend(size).copy_from_slice(&buffer);
                            if conn.write_buffer(b).await.is_err() {
                                break;
                            }
                        }
                    }
                    total += size as u64;
                }
                total
            } else {
                let mut total = 0u64;
                match copy {
                    CopyMode::Read => {
                        let mut buffer = vec![0u8; size];
                        loop {
                            if Instant::now() >= deadline {
                                break;
                            }
                            match conn.read(&mut buffer).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => total += n as u64,
                            }
                        }
                    }
                    CopyMode::Buffer => loop {
                        if Instant::now() >= deadline {
                            break;
                        }
                        match conn.wait_read_buffer().await {
                            Ok(Some(buffer)) => total += buffer.len() as u64,
                            Ok(None) | Err(_) => break,
                        }
                    },
                }
                total
            };
            counter.fetch_add(total, Ordering::Relaxed);
            let _ = conn.close().await;
            let _: io::Result<()> = Ok(());
            Ok::<(), io::Error>(())
        }));
    }
    tokio::time::sleep_until(deadline.into()).await;
    let bytes = counter.load(Ordering::Relaxed);
    let seconds = options.seconds as f64;
    println!(
        "{} streams, {} bytes in {:.0}s = {:.2} Gbps ({:.1} MiB/s), copy={}",
        options.streams,
        bytes,
        seconds,
        bytes as f64 * 8.0 / seconds / 1e9,
        bytes as f64 / seconds / (1u64 << 20) as f64,
        if options.copy == CopyMode::Read { "read" } else { "buffer" },
    );
    for task in tasks {
        task.abort();
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let options = parse_args()?;
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if options.workers > 0 {
        builder.worker_threads(options.workers);
    }
    builder.build()?.block_on(async move {
        match options.role.as_str() {
            "server" => run_server(options).await,
            _ => run_client(options).await,
        }
    })
}
