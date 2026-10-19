//! A minimal `snell-server` compatible with the official configuration file.
//!
//! ```text
//! snell-server -c snell.conf [-l error|warn|info|debug|trace] [--protocol v5|v6]
//! ```
//!
//! ```ini
//! [snell-server]
//! listen = 0.0.0.0:6160
//! psk = your-pre-shared-key
//! obfs = none      # v5 only: none | http | tls
//! mode = default   # v6 only: default | unshaped | unsafe-raw
//! ```
//!
//! Without `--protocol`, a configuration with a `mode` key runs the v6
//! server and anything else runs the v5 server, which also accepts v4 clients.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use snell::{Buffer, CloseHandler, Conn, Context, Handler, ObfsMode, PacketConn, Service, Socksaddr, TcpConn, v5, v6};
use tokio::net::{TcpListener, TcpStream, UdpSocket, lookup_host};

struct Options {
    config: String,
    log_level: String,
    protocol: Option<String>,
}

fn parse_args() -> io::Result<Options> {
    let mut options = Options { config: String::new(), log_level: "error".into(), protocol: None };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| io::Error::other(format!("missing value for {arg}")));
        match arg.as_str() {
            "-c" | "--config" => options.config = value()?,
            "-l" | "--log-level" => options.log_level = value()?,
            "--protocol" => options.protocol = Some(value()?),
            "-h" | "--help" => {
                println!("usage: snell-server -c <config> [-l <level>] [--protocol v5|v6]");
                std::process::exit(0);
            }
            _ => return Err(io::Error::other(format!("unknown argument: {arg}"))),
        }
    }
    if options.config.is_empty() {
        return Err(io::Error::other("missing -c <config>"));
    }
    Ok(options)
}

fn parse_config(content: &str) -> io::Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    let mut in_section = false;
    for line in content.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_section = line == "[snell-server]";
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(io::Error::other(format!("invalid configuration line: {line}")));
        };
        values.insert(key.trim().to_lowercase(), value.trim().to_string());
    }
    Ok(values)
}

async fn resolve(destination: &Socksaddr) -> io::Result<SocketAddr> {
    if let Some(addr) = destination.socket_addr() {
        return Ok(addr);
    }
    lookup_host((destination.fqdn.as_str(), destination.port))
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("no address for {destination}")))
}

async fn copy_half(source: &Arc<dyn Conn>, destination: &Arc<dyn Conn>) -> io::Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = source.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        destination.write(&buf[..n]).await?;
    }
}

/// Copies both directions, half-closing each side when its source ends.
async fn copy_conn(source: Arc<dyn Conn>, destination: Arc<dyn Conn>) -> io::Result<()> {
    async fn pipe(from: Arc<dyn Conn>, to: Arc<dyn Conn>) -> io::Result<()> {
        let result = copy_half(&from, &to).await;
        match &result {
            Ok(()) => {
                let _ = to.close_write().await;
            }
            Err(_) => {
                let _ = to.close().await;
            }
        }
        result
    }
    let (upload, download) =
        tokio::join!(pipe(source.clone(), destination.clone()), pipe(destination.clone(), source.clone()));
    let _ = source.close().await;
    let _ = destination.close().await;
    upload.and(download)
}

struct RouteHandler {
    verbose: bool,
}

impl Handler for RouteHandler {
    fn new_connection(
        &self,
        _: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        let verbose = self.verbose;
        tokio::spawn(async move {
            let result = async {
                let addr = resolve(&destination).await?;
                let upstream: Arc<dyn Conn> = Arc::new(TcpConn::new(TcpStream::connect(addr).await?)?);
                copy_conn(conn.clone(), upstream).await
            }
            .await;
            if let Err(err) = &result {
                let _ = conn.close().await;
                if verbose {
                    eprintln!("tcp {source} -> {destination}: {err}");
                }
            }
            if let Some(on_close) = on_close {
                on_close(result.err());
            }
        });
    }

    fn new_packet_connection(
        &self,
        _: Context,
        conn: Arc<dyn PacketConn>,
        source: Socksaddr,
        _: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        let verbose = self.verbose;
        tokio::spawn(async move {
            let result = relay_packets(conn.clone()).await;
            let _ = conn.close().await;
            if let Err(err) = &result
                && verbose
            {
                eprintln!("udp {source}: {err}");
            }
            if let Some(on_close) = on_close {
                on_close(result.err());
            }
        });
    }
}

async fn relay_packets(conn: Arc<dyn PacketConn>) -> io::Result<()> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let downlink = {
        let (socket, conn) = (socket.clone(), conn.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, addr)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let buffer = Buffer::from_slice_with_headroom(&buf[..n], conn.front_headroom(), conn.rear_headroom());
                if conn.write_packet(buffer, Socksaddr::from(addr)).await.is_err() {
                    return;
                }
            }
        })
    };
    let result = async {
        loop {
            let mut buffer = Buffer::new_packet();
            let destination = conn.read_packet(&mut buffer).await?;
            if let Ok(addr) = resolve(&destination).await {
                let _ = socket.send_to(buffer.bytes(), addr).await;
            }
        }
    }
    .await;
    downlink.abort();
    result
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let options = parse_args()?;
    let config = parse_config(&std::fs::read_to_string(&options.config)?)?;
    let listen = config.get("listen").ok_or_else(|| io::Error::other("missing listen"))?;
    let psk = config.get("psk").ok_or_else(|| io::Error::other("missing psk"))?.as_bytes().to_vec();
    let verbose = !matches!(options.log_level.as_str(), "error");
    let handler = Arc::new(RouteHandler { verbose });
    let protocol =
        options.protocol.clone().unwrap_or_else(|| if config.contains_key("mode") { "v6".into() } else { "v5".into() });
    let service: Arc<dyn Service> = match protocol.as_str() {
        "v4" | "v5" => {
            let obfs_mode: ObfsMode = config.get("obfs").map(String::as_str).unwrap_or("none").parse()?;
            Arc::new(v5::Service::new(v5::ServiceOptions { psk, obfs_mode, handler })?)
        }
        "v6" => {
            let mode = v6::parse_mode(config.get("mode").map(String::as_str).unwrap_or(""))?;
            Arc::new(v6::Service::new(v6::ServerOptions { psk, mode, handler })?)
        }
        _ => return Err(io::Error::other(format!("unknown protocol: {protocol}"))),
    };
    let listener = TcpListener::bind(listen).await?;
    if verbose {
        eprintln!("snell-server ({protocol}) listening on {}", listener.local_addr()?);
    }
    loop {
        let (stream, addr) = listener.accept().await?;
        let service = service.clone();
        tokio::spawn(async move {
            let Ok(conn) = TcpConn::new(stream) else {
                return;
            };
            let conn: Arc<dyn Conn> = Arc::new(conn);
            if let Err(err) = service.new_connection(Context::new(), conn.clone(), Socksaddr::from(addr), None).await {
                let _ = err.conn.close().await;
                if verbose {
                    eprintln!("{err}");
                }
            }
        });
    }
}
