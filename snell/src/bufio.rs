//! A port of the parts of Go's `bufio.Reader` whose buffering is observable
//! in snell: the v4 record reader checks how many bytes are buffered after a
//! zero chunk, and the HTTP obfs head reader leaves its read-ahead buffered.

use std::io;

use crate::error;
use crate::net::Conn;

const DEFAULT_BUF_SIZE: usize = 4096;

pub(crate) struct BufReader {
    buf: Box<[u8]>,
    r: usize,
    w: usize,
}

impl BufReader {
    pub(crate) fn new() -> Self {
        BufReader { buf: vec![0; DEFAULT_BUF_SIZE].into_boxed_slice(), r: 0, w: 0 }
    }

    /// `Buffered()`.
    pub(crate) fn buffered(&self) -> usize {
        self.w - self.r
    }

    /// `Read(p)`: returns EOF as an error, like Go.
    pub(crate) async fn read(&mut self, upstream: &dyn Conn, p: &mut [u8]) -> io::Result<usize> {
        if p.is_empty() {
            return Ok(0);
        }
        if self.r == self.w {
            if p.len() >= self.buf.len() {
                // Large read, empty buffer: read directly into p.
                return match upstream.read(p).await? {
                    0 => Err(error::eof()),
                    n => Ok(n),
                };
            }
            // One read.
            self.r = 0;
            self.w = 0;
            let n = upstream.read(&mut self.buf).await?;
            if n == 0 {
                return Err(error::eof());
            }
            self.w = n;
        }
        let n = (self.w - self.r).min(p.len());
        p[..n].copy_from_slice(&self.buf[self.r..self.r + n]);
        self.r += n;
        Ok(n)
    }

    /// `ReadByte()`.
    pub(crate) async fn read_byte(&mut self, upstream: &dyn Conn) -> io::Result<u8> {
        while self.r == self.w {
            self.fill(upstream).await?;
        }
        let b = self.buf[self.r];
        self.r += 1;
        Ok(b)
    }

    async fn fill(&mut self, upstream: &dyn Conn) -> io::Result<()> {
        if self.r > 0 {
            self.buf.copy_within(self.r..self.w, 0);
            self.w -= self.r;
            self.r = 0;
        }
        let w = self.w;
        let n = upstream.read(&mut self.buf[w..]).await?;
        if n == 0 {
            return Err(error::eof());
        }
        self.w += n;
        Ok(())
    }

    /// `io.ReadFull(reader, buf)`.
    pub(crate) async fn read_full(&mut self, upstream: &dyn Conn, buf: &mut [u8]) -> io::Result<()> {
        let mut n = 0;
        while n < buf.len() {
            match self.read(upstream, &mut buf[n..]).await {
                Ok(m) => n += m,
                Err(err) => {
                    return Err(if n > 0 && error::is_bare_eof(&err) { error::unexpected_eof() } else { err });
                }
            }
        }
        Ok(())
    }
}
