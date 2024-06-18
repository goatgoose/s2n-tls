use std::{fmt, io};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use hyper::rt::{Read, Write};
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use tower_service::Service;
use s2n_tls::connection::Builder;
use s2n_tls::config::Config;
use s2n_tls_tokio::{TlsConnector, TlsStream};
use http::uri::Uri;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct HttpsConnector<T, B = Config>
where
    B: Builder,
    <B as Builder>::Output: Unpin,
{
    http: T,
    builder: B,
}

impl<T, B> HttpsConnector<T, B>
where
    B: Builder,
    <B as Builder>::Output: Unpin,
{
    pub fn new(builder: B) -> HttpsConnector<HttpConnector, B> {
        HttpsConnector {
            http: HttpConnector::new(),
            builder,
        }
    }
}

impl<T, B> Service<Uri> for HttpsConnector<T, B>
where
    T: Service<Uri>,
    T::Response: Read + Write + Connection + Unpin + Send + 'static,
    T::Future: Send + 'static,
    T::Error: Into<BoxError>,
    B: Builder<Output = s2n_tls::connection::Connection> + 'static,
    <B as Builder>::Output: Unpin,
{
    type Response = TokioIo<TlsStream<TokioIo<T::Response>>>;
    type Error = BoxError;
    type Future = Pin<Box<
        dyn Future<Output = Result<TokioIo<TlsStream<TokioIo<T::Response>>>, BoxError>>
    >>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.http.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        // Only permit HTTP over TLS.
        if req.scheme() != Some(&http::uri::Scheme::HTTPS) {
            return Box::pin(async move { Err(UnsupportedScheme.into()) })
        }

        let builder = self.builder.clone();
        let connector: TlsConnector<B> = TlsConnector::new(builder);

        let host = req.host().unwrap_or("").to_owned();
        let call = self.http.call(req);
        Box::pin(async move {
            let tcp = call.await.map_err(Into::into)?;
            Ok(TokioIo::new(connector.connect(&host, TokioIo::new(tcp)).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?))
        })
    }
}

#[derive(Debug)]
struct UnsupportedScheme;

impl fmt::Display for UnsupportedScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("The provided URI scheme is not supported")
    }
}

impl std::error::Error for UnsupportedScheme {}
