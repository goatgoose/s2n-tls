use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use hyper::rt::{Read, ReadBufCursor, Write};
use s2n_tls_tokio::TlsStream;
use tokio_rustls::TlsStream as RustlsStream;

pub enum MaybeHttpsStream<T: Read + Write + Connection + Unpin> {
    Http(T),
    Https(TokioIo<TlsStream<TokioIo<T>>>)
}

impl<T: Read + Write + Connection + Unpin> Connection for MaybeHttpsStream<T> {
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(stream) => stream.connected(),
            MaybeHttpsStream::Https(stream) => stream.inner().get_ref().connected()
        }
    }
}

impl<T: Read + Write + Connection + Unpin> Read for MaybeHttpsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>
    ) -> Poll<Result<(), Error>> {
        match Pin::get_mut(self) {
            Self::Http(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Https(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<T: Read + Write + Connection + Unpin> Write for MaybeHttpsStream<T>{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<Result<usize, Error>> {
        match Pin::get_mut(self) {
            Self::Http(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Https(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_flush(cx),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_flush(cx)
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_shutdown(cx),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_shutdown(cx)
        }
    }
}
