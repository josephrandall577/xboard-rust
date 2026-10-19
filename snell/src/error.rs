//! Error helpers.
//!
//! Errors are plain [`std::io::Error`] values. The Go implementation relies on
//! sentinel errors (`io.EOF`, `net.ErrClosed`, `snell.ErrBadVersion`, ...) that
//! survive wrapping; the helpers here keep the same information inside
//! `io::Error` so that [`is_eof`], [`is_closed`] and [`has_code`] can look it up
//! through any number of wrapping layers.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::sync::Arc;

/// Sentinel snell errors, mirroring the exported `Err*` values of the Go package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    BadVersion,
    ReservedNonZero,
    PayloadTooLarge,
    UnsupportedCommand,
    UnexpectedReply,
    MissingPsk,
    NoUsers,
    BadUserKey,
    DuplicateUserKey,
}

impl ErrorCode {
    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::BadVersion => "snell: bad header version",
            ErrorCode::ReservedNonZero => "snell: reserved header octet is non-zero",
            ErrorCode::PayloadTooLarge => "snell: payload length exceeds maximum",
            ErrorCode::UnsupportedCommand => "snell: unsupported command",
            ErrorCode::UnexpectedReply => "snell: unexpected reply opcode",
            ErrorCode::MissingPsk => "snell: missing pre-shared key",
            ErrorCode::NoUsers => "snell: no users",
            ErrorCode::BadUserKey => "snell: bad user key",
            ErrorCode::DuplicateUserKey => "snell: duplicate user key",
        }
    }

    fn kind(self) -> io::ErrorKind {
        match self {
            ErrorCode::MissingPsk | ErrorCode::NoUsers | ErrorCode::DuplicateUserKey => io::ErrorKind::InvalidInput,
            ErrorCode::BadUserKey => io::ErrorKind::PermissionDenied,
            _ => io::ErrorKind::InvalidData,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl StdError for ErrorCode {}

impl From<ErrorCode> for io::Error {
    fn from(code: ErrorCode) -> Self {
        io::Error::new(code.kind(), code)
    }
}

/// The equivalent of Go's `io.EOF`.
#[derive(Debug)]
struct Eof;

impl fmt::Display for Eof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EOF")
    }
}

impl StdError for Eof {}

/// The equivalent of Go's `net.ErrClosed`.
#[derive(Debug)]
struct Closed;

impl fmt::Display for Closed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("use of closed network connection")
    }
}

impl StdError for Closed {}

/// `E.Cause(cause, message)`: renders as `message: cause`.
#[derive(Debug)]
struct Cause {
    message: String,
    cause: io::Error,
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.message, self.cause)
    }
}

impl StdError for Cause {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.cause)
    }
}

/// `E.Extend(cause, message)`: renders as `cause: message`.
#[derive(Debug)]
struct Extend {
    message: String,
    cause: io::Error,
}

impl fmt::Display for Extend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.cause, self.message)
    }
}

impl StdError for Extend {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.cause)
    }
}

/// An error stored once and handed out to several callers (`sync.Once` results).
#[derive(Debug, Clone)]
struct Shared(Arc<io::Error>);

impl fmt::Display for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl StdError for Shared {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref())
    }
}

fn walk(err: &io::Error, predicate: &dyn Fn(&(dyn StdError + Send + Sync + 'static)) -> bool) -> bool {
    let Some(inner) = err.get_ref() else {
        return false;
    };
    if predicate(inner) {
        return true;
    }
    if let Some(cause) = inner.downcast_ref::<Cause>() {
        return walk(&cause.cause, predicate);
    }
    if let Some(extend) = inner.downcast_ref::<Extend>() {
        return walk(&extend.cause, predicate);
    }
    if let Some(shared) = inner.downcast_ref::<Shared>() {
        return walk(&shared.0, predicate);
    }
    false
}

/// Returns an error equivalent to Go's `io.EOF`.
pub fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, Eof)
}

/// Returns an error equivalent to Go's `io.ErrUnexpectedEOF`.
pub fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

/// Returns an error equivalent to Go's `net.ErrClosed`.
pub fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, Closed)
}

/// Returns an error equivalent to Go's `os.ErrDeadlineExceeded`.
pub fn timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

/// Returns an error equivalent to Go's `os.ErrInvalid`.
pub fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid argument")
}

/// Returns an error equivalent to Go's `io.ErrShortBuffer`.
pub fn short_buffer() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "short buffer")
}

/// Returns an error equivalent to Go's `context.Canceled`.
pub fn canceled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "context canceled")
}

/// Reports whether `err` is (or wraps) Go's `io.EOF`.
pub fn is_eof(err: &io::Error) -> bool {
    walk(err, &|inner| inner.is::<Eof>())
}

/// Reports whether `err` is Go's `io.EOF` itself, without any wrapping.
pub(crate) fn is_bare_eof(err: &io::Error) -> bool {
    err.get_ref().is_some_and(|inner| inner.is::<Eof>())
}

/// Reports whether `err` is (or wraps) Go's `net.ErrClosed`.
pub fn is_closed(err: &io::Error) -> bool {
    walk(err, &|inner| inner.is::<Closed>())
}

/// Reports whether `err` is (or wraps) the given sentinel error.
pub fn has_code(err: &io::Error, code: ErrorCode) -> bool {
    walk(err, &|inner| inner.downcast_ref::<ErrorCode>() == Some(&code))
}

/// `E.New(...)` for protocol violations.
pub(crate) fn new_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// `E.New(...)` for invalid arguments and options.
pub(crate) fn new_invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// `E.Cause(err, message)`.
pub(crate) fn cause(err: io::Error, message: impl Into<String>) -> io::Error {
    io::Error::new(err.kind(), Cause { message: message.into(), cause: err })
}

/// `E.Extend(err, message)`.
pub(crate) fn extend(err: io::Error, message: impl Into<String>) -> io::Error {
    io::Error::new(err.kind(), Extend { message: message.into(), cause: err })
}

/// `E.Extend(code, message)`.
pub(crate) fn extend_code(code: ErrorCode, message: impl fmt::Display) -> io::Error {
    extend(code.into(), message.to_string())
}

/// `E.Errors(a, b)`: keeps the first error.
pub(crate) fn first_error(first: Option<io::Error>, second: io::Result<()>) -> Option<io::Error> {
    match first {
        Some(err) => Some(err),
        None => second.err(),
    }
}

/// A cloneable io error result, used to replay `sync.Once` results.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedResult(Option<Arc<io::Error>>);

impl SharedResult {
    pub(crate) fn new(result: io::Result<()>) -> Self {
        SharedResult(result.err().map(Arc::new))
    }

    pub(crate) fn get(&self) -> io::Result<()> {
        match &self.0 {
            None => Ok(()),
            Some(err) => Err(io::Error::new(err.kind(), Shared(err.clone()))),
        }
    }
}

/// Returns two errors sharing the same cause, for an error that is both
/// reported to a close handler and returned.
pub(crate) fn duplicate(err: io::Error) -> (io::Error, io::Error) {
    let shared = SharedResult::new(Err(err));
    (shared.get().unwrap_err(), shared.get().unwrap_err())
}
