mod udp_stream;

use std::io::{self, Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub(crate) use self::udp_stream::UdpStream;
use crate::error::MemcacheError;

#[cfg(all(feature = "tls", not(feature = "rustls")))]
use openssl::ssl::SslStream;
#[cfg(feature = "rustls")]
use rustls::{ClientConnection, StreamOwned};

pub enum Stream {
    Tcp(TcpStream),
    Udp(UdpStream),
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(all(feature = "tls", not(feature = "rustls")))]
    Tls(SslStream<TcpStream>),
    #[cfg(feature = "rustls")]
    Tls(StreamOwned<ClientConnection, TcpStream>),
}

impl Stream {
    pub(super) fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), MemcacheError> {
        match self {
            &mut Stream::Tcp(ref conn) => conn.set_read_timeout(timeout)?,
            #[cfg(unix)]
            &mut Stream::Unix(ref conn) => conn.set_read_timeout(timeout)?,
            #[cfg(any(feature = "tls", feature = "rustls"))]
            &mut Stream::Tls(ref stream) => stream.get_ref().set_read_timeout(timeout)?,
            &mut Stream::Udp(ref conn) => conn.set_read_timeout(timeout)?,
        }
        Ok(())
    }

    pub(super) fn set_write_timeout(&mut self, timeout: Option<Duration>) -> Result<(), MemcacheError> {
        match self {
            &mut Stream::Tcp(ref conn) => conn.set_write_timeout(timeout)?,
            #[cfg(unix)]
            &mut Stream::Unix(ref conn) => conn.set_write_timeout(timeout)?,
            #[cfg(any(feature = "tls", feature = "rustls"))]
            &mut Stream::Tls(ref stream) => stream.get_ref().set_write_timeout(timeout)?,
            &mut Stream::Udp(ref conn) => conn.set_write_timeout(timeout)?,
        }
        Ok(())
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.read(buf),
            Stream::Udp(stream) => stream.read(buf),
            #[cfg(unix)]
            Stream::Unix(stream) => stream.read(buf),
            #[cfg(any(feature = "tls", feature = "rustls"))]
            Stream::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.write(buf),
            Stream::Udp(stream) => stream.write(buf),
            #[cfg(unix)]
            Stream::Unix(stream) => stream.write(buf),
            #[cfg(any(feature = "tls", feature = "rustls"))]
            Stream::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.flush(),
            Stream::Udp(stream) => stream.flush(),
            #[cfg(unix)]
            Stream::Unix(stream) => stream.flush(),
            #[cfg(any(feature = "tls", feature = "rustls"))]
            Stream::Tls(stream) => stream.flush(),
        }
    }
}
