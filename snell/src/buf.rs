//! A port of sing's `buf.Buffer`: a byte buffer with front headroom, used to
//! build records in place without copying the payload.

use std::cell::RefCell;
use std::fmt;
use std::io;

use crate::error;

/// Default stream buffer size (`buf.BufferSize`).
pub const BUFFER_SIZE: usize = 32 * 1024;
/// Default packet buffer size (`buf.UDPBufferSize`).
pub const UDP_BUFFER_SIZE: usize = 16 * 1024;

/// Buffers are recycled through a per-thread free list: record buffers are
/// short-lived and a steady stream allocates and frees several per record.
/// Recycled storage is still fully initialized, so skipping `vec![0; size]`
/// only avoids a memset; its contents are never visible through `bytes()`.
const POOL_LIMIT: usize = 8;
const POOL_MAX_CAPACITY: usize = 128 * 1024;

thread_local! {
    static POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

fn take_buffer(size: usize) -> Vec<u8> {
    let mut data = POOL.try_with(|pool| pool.borrow_mut().pop()).ok().flatten().unwrap_or_default();
    if data.len() < size {
        data.resize(size, 0);
    } else {
        data.truncate(size);
    }
    data
}

fn recycle_buffer(data: Vec<u8>) {
    if data.is_empty() || data.capacity() > POOL_MAX_CAPACITY {
        return;
    }
    let _ = POOL.try_with(|pool| {
        let mut pool = pool.borrow_mut();
        if pool.len() < POOL_LIMIT {
            pool.push(data);
        }
    });
}

/// A byte buffer with a movable start (front headroom) and an adjustable
/// logical capacity (rear headroom).
///
/// Unlike the Go type, [`Buffer::extend`] and [`Buffer::extend_header`] grow
/// the backing storage instead of panicking when the headroom is insufficient.
#[derive(Clone, Default)]
pub struct Buffer {
    data: Vec<u8>,
    start: usize,
    end: usize,
    capacity: usize,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        recycle_buffer(std::mem::take(&mut self.data));
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("capacity", &self.capacity)
            .field("raw_capacity", &self.data.len())
            .finish()
    }
}

impl Buffer {
    /// `buf.New()`.
    pub fn new() -> Self {
        Self::with_capacity(BUFFER_SIZE)
    }

    /// `buf.NewPacket()`.
    pub fn new_packet() -> Self {
        Self::with_capacity(UDP_BUFFER_SIZE)
    }

    /// `buf.NewSize(size)`.
    pub fn with_capacity(size: usize) -> Self {
        Buffer { data: take_buffer(size), start: 0, end: 0, capacity: size }
    }

    /// `buf.As(data)`: a full buffer holding `data`.
    pub fn from_vec(data: Vec<u8>) -> Self {
        let len = data.len();
        Buffer { data, start: 0, end: len, capacity: len }
    }

    /// Creates a buffer holding a copy of `data` with the given headroom.
    pub fn from_slice_with_headroom(data: &[u8], front: usize, rear: usize) -> Self {
        let mut buffer = Self::with_capacity(front + data.len() + rear);
        buffer.resize(front, 0);
        buffer.extend(data.len()).copy_from_slice(data);
        buffer
    }

    pub fn start(&self) -> usize {
        self.start
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }

    pub fn is_full(&self) -> bool {
        self.end == self.capacity
    }

    pub fn cap(&self) -> usize {
        self.capacity
    }

    pub fn raw_cap(&self) -> usize {
        self.data.len()
    }

    pub fn free_len(&self) -> usize {
        self.capacity.saturating_sub(self.end)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.start..self.end]
    }

    pub fn free_bytes_mut(&mut self) -> &mut [u8] {
        let capacity = self.capacity.max(self.end);
        &mut self.data[self.end..capacity]
    }

    /// `From(n)`: the content after the first `n` bytes.
    pub fn from_offset(&self, n: usize) -> &[u8] {
        &self.data[self.start + n..self.end]
    }

    /// Mutable `From(n)`.
    pub fn from_offset_mut(&mut self, n: usize) -> &mut [u8] {
        &mut self.data[self.start + n..self.end]
    }

    /// `To(n)`.
    pub fn to(&self, n: usize) -> &[u8] {
        &self.data[self.start..self.start + n]
    }

    /// `Range(start, end)`.
    pub fn range(&self, start: usize, end: usize) -> &[u8] {
        &self.data[self.start + start..self.start + end]
    }

    /// Mutable `Range(start, end)`.
    pub fn range_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
        &mut self.data[self.start + start..self.start + end]
    }

    fn grow_back(&mut self, end: usize) {
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        if end > self.capacity {
            self.capacity = end;
        }
    }

    /// `Extend(n)`: appends `n` bytes and returns them.
    pub fn extend(&mut self, n: usize) -> &mut [u8] {
        let end = self.end + n;
        self.grow_back(end);
        let start = self.end;
        self.end = end;
        &mut self.data[start..end]
    }

    /// `ExtendHeader(n)`: prepends `n` bytes and returns them.
    pub fn extend_header(&mut self, n: usize) -> &mut [u8] {
        if self.start < n {
            let shift = n - self.start;
            let mut data = vec![0; self.data.len() + shift];
            data[self.start + shift..self.end + shift].copy_from_slice(&self.data[self.start..self.end]);
            self.data = data;
            self.start += shift;
            self.end += shift;
            self.capacity += shift;
        }
        self.start -= n;
        &mut self.data[self.start..self.start + n]
    }

    /// `Advance(n)`.
    pub fn advance(&mut self, n: usize) {
        self.start += n;
        if self.end < self.start {
            self.end = self.start;
        }
    }

    /// `Truncate(n)`.
    pub fn truncate(&mut self, n: usize) {
        self.end = self.start + n;
    }

    /// `Resize(start, end)`.
    pub fn resize(&mut self, start: usize, len: usize) {
        self.start = start;
        self.end = start + len;
        self.grow_back(self.end);
    }

    /// `Reserve(n)`: hides `n` bytes at the end of the capacity.
    pub fn reserve(&mut self, n: usize) {
        self.capacity = self.capacity.saturating_sub(n);
    }

    /// `OverCap(n)`: restores `n` bytes hidden by [`Buffer::reserve`].
    pub fn over_cap(&mut self, n: usize) {
        self.capacity = (self.capacity + n).min(self.data.len());
    }

    /// `Write(data)`: copies as much as fits into the free space.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let free = self.free_bytes_mut();
        let n = free.len().min(data.len());
        free[..n].copy_from_slice(&data[..n]);
        self.end += n;
        n
    }

    /// Appends all of `data`, growing the buffer if needed.
    pub fn write_all(&mut self, data: &[u8]) {
        self.extend(data.len()).copy_from_slice(data);
    }

    /// `WriteByte(b)`.
    pub fn write_byte(&mut self, b: u8) {
        self.extend(1)[0] = b;
    }

    /// `ReadByte()`: returns EOF when empty.
    pub fn read_byte(&mut self) -> io::Result<u8> {
        if self.is_empty() {
            return Err(error::eof());
        }
        let b = self.data[self.start];
        self.start += 1;
        Ok(b)
    }

    /// `ReadBytes(n)`: returns EOF when fewer than `n` bytes remain.
    pub fn read_bytes(&mut self, n: usize) -> io::Result<&[u8]> {
        if self.len() < n {
            return Err(error::eof());
        }
        let start = self.start;
        self.start += n;
        Ok(&self.data[start..start + n])
    }

    /// `io.ReadFull(buffer, out)`: EOF when empty, unexpected EOF when short.
    pub fn read_full(&mut self, out: &mut [u8]) -> io::Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        if self.is_empty() {
            return Err(error::eof());
        }
        let n = self.len().min(out.len());
        out[..n].copy_from_slice(&self.data[self.start..self.start + n]);
        self.start += n;
        if n < out.len() {
            return Err(error::unexpected_eof());
        }
        Ok(())
    }

    /// Consumes the buffer and returns its content.
    pub fn into_vec(mut self) -> Vec<u8> {
        if self.start == 0 {
            self.data.truncate(self.end);
            std::mem::take(&mut self.data)
        } else {
            self.bytes().to_vec()
        }
    }
}
