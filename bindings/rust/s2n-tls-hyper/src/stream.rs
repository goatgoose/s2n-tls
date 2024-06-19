use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use hyper::rt::{Read, ReadBufCursor, Write};
use s2n_tls_tokio::TlsStream;
use tokio_rustls::TlsStream as RustlsStream;
use s2n_tls::connection::Builder;

pub enum MaybeHttpsStream<T, B>
where
    T: Read + Write + Connection + Unpin,
    B: Builder,
    <B as Builder>::Output: Unpin,
{
    Http(T),
    Https(TokioIo<TlsStream<TokioIo<T>, B::Output>>)
}

impl<T, B> Connection for MaybeHttpsStream<T, B>
where
    T: Read + Write + Connection + Unpin,
    B: Builder,
    <B as Builder>::Output: Unpin,
{
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(stream) => stream.connected(),
            MaybeHttpsStream::Https(stream) => stream.inner().get_ref().connected()
        }
    }
}

impl<T, B> Read for MaybeHttpsStream<T, B>
where
    T: Read + Write + Connection + Unpin,
    B: Builder,
    <B as Builder>::Output: Unpin,
{
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

impl<T, B> Write for MaybeHttpsStream<T, B>
where
    T: Read + Write + Connection + Unpin,
    B: Builder,
    <B as Builder>::Output: Unpin,
{
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
