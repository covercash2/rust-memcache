use std::net::TcpStream;
use std::ops::{Deref, DerefMut};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

use crate::error::MemcacheError;

use crate::protocol::{AsciiProtocol, BinaryProtocol, Protocol, ProtocolTrait};
use crate::stream::Stream;
use crate::stream::UdpStream;
#[cfg(all(feature = "tls", not(feature = "rustls")))]
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use r2d2::ManageConnection;

/// A connection to the memcached server
pub struct Connection {
    pub protocol: Protocol,
    pub url: Arc<String>,
}

impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.protocol
    }
}

impl Deref for Connection {
    type Target = Protocol;
    fn deref(&self) -> &Self::Target {
        &self.protocol
    }
}

/// Memcache connection manager implementing rd2d Pool ManageConnection
pub struct ConnectionManager {
    url: Url,
}

impl ConnectionManager {
    /// Initialize connection manager with given Url
    pub fn new(url: Url) -> Self {
        Self { url }
    }
}

impl ManageConnection for ConnectionManager {
    type Connection = Connection;
    type Error = MemcacheError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let url = &self.url;
        let mut connection = Connection::connect(url)?;
        if url.has_authority() && !url.username().is_empty() && url.password().is_some() {
            let username = url.username();
            let password = url.password().unwrap();
            connection.auth(username, password)?;
        }
        Ok(connection)
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.version().map(|_| ())
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        // TODO: fix this
        false
    }
}

enum Transport {
    Tcp(TcpOptions),
    Udp(UdpOptions),
    #[cfg(unix)]
    Unix,
    #[cfg(any(feature = "tls", feature = "rustls"))]
    Tls(TlsOptions),
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
struct TlsOptions {
    tcp_options: TcpOptions,
    ca_path: Option<String>,
    key_path: Option<String>,
    cert_path: Option<String>,
    verify_mode: SslVerifyMode,
}

#[cfg(feature = "rustls")]
struct TlsOptions {
    tcp_options: TcpOptions,
    ca_path: Option<String>,
    key_path: Option<String>,
    cert_path: Option<String>,
    skip_verify: bool,
}

struct TcpOptions {
    timeout: Option<Duration>,
    nodelay: bool,
}

struct UdpOptions {
    bind_addr: Option<String>,
}

impl UdpOptions {
    fn from_url(url: &Url) -> Self {
        let bind_addr = url.query_pairs().find(|(k, _)| k == "bind").map(|(_, v)| v.to_string());
        UdpOptions { bind_addr }
    }
}

#[cfg(any(feature = "tls", feature = "rustls"))]
fn get_param(url: &Url, key: &str) -> Option<String> {
    return url
        .query_pairs()
        .find(|&(ref k, ref _v)| k == key)
        .map(|(_k, v)| v.to_string());
}

#[cfg(any(feature = "tls", feature = "rustls"))]
fn validate_key_cert_paths(key_path: &Option<String>, cert_path: &Option<String>) -> Result<(), MemcacheError> {
    if key_path.is_some() && cert_path.is_none() {
        return Err(MemcacheError::BadURL(
            "cert_path must be specified when key_path is specified".into(),
        ));
    } else if key_path.is_none() && cert_path.is_some() {
        return Err(MemcacheError::BadURL(
            "key_path must be specified when cert_path is specified".into(),
        ));
    }
    Ok(())
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl TlsOptions {
    fn from_url(url: &Url) -> Result<Self, MemcacheError> {
        let verify_mode = match get_param(url, "verify_mode").as_ref().map(String::as_str) {
            Some("none") => SslVerifyMode::NONE,
            Some("peer") => SslVerifyMode::PEER,
            Some(_) => {
                return Err(MemcacheError::BadURL(
                    "unknown verify_mode, expected 'none' or 'peer'".into(),
                ));
            }
            None => SslVerifyMode::PEER,
        };

        let ca_path = get_param(url, "ca_path");
        let key_path = get_param(url, "key_path");
        let cert_path = get_param(url, "cert_path");

        validate_key_cert_paths(&key_path, &cert_path)?;

        Ok(TlsOptions {
            tcp_options: TcpOptions::from_url(url),
            ca_path: ca_path,
            key_path: key_path,
            cert_path: cert_path,
            verify_mode: verify_mode,
        })
    }
}

#[cfg(feature = "rustls")]
impl TlsOptions {
    fn from_url(url: &Url) -> Result<Self, MemcacheError> {
        let skip_verify = match get_param(url, "verify_mode").as_ref().map(String::as_str) {
            Some("none") => true,
            Some("peer") | None => false,
            Some(_) => {
                return Err(MemcacheError::BadURL(
                    "unknown verify_mode, expected 'none' or 'peer'".into(),
                ));
            }
        };

        let ca_path = get_param(url, "ca_path");
        let key_path = get_param(url, "key_path");
        let cert_path = get_param(url, "cert_path");

        validate_key_cert_paths(&key_path, &cert_path)?;

        Ok(TlsOptions {
            tcp_options: TcpOptions::from_url(url),
            ca_path,
            key_path,
            cert_path,
            skip_verify,
        })
    }
}

impl TcpOptions {
    fn from_url(url: &Url) -> Self {
        let nodelay = !url
            .query_pairs()
            .any(|(ref k, ref v)| k == "tcp_nodelay" && v == "false");
        let timeout = url
            .query_pairs()
            .find(|&(ref k, ref _v)| k == "timeout")
            .and_then(|(ref _k, ref v)| v.parse::<f64>().ok())
            .map(Duration::from_secs_f64);
        TcpOptions {
            nodelay: nodelay,
            timeout: timeout,
        }
    }
}

impl Transport {
    fn from_url(url: &Url) -> Result<Self, MemcacheError> {
        let mut parts = url.scheme().splitn(2, "+");
        match parts.next() {
            Some(part) if part == "memcache" => (),
            _ => {
                return Err(MemcacheError::BadURL(
                    "memcache URL's scheme should start with 'memcache'".into(),
                ));
            }
        }

        // scheme has highest priority
        if let Some(proto) = parts.next() {
            return match proto {
                "tcp" => Ok(Transport::Tcp(TcpOptions::from_url(url))),
                "udp" => Ok(Transport::Udp(UdpOptions::from_url(url))),
                #[cfg(unix)]
                "unix" => Ok(Transport::Unix),
                #[cfg(any(feature = "tls", feature = "rustls"))]
                "tls" => Ok(Transport::Tls(TlsOptions::from_url(url)?)),
                _ => Err(MemcacheError::BadURL(
                    "memcache URL's scheme should be 'memcache+tcp' or 'memcache+udp' or 'memcache+unix' or 'memcache+tls'".into(),
                )),
            };
        }

        let is_udp = url.query_pairs().any(|(ref k, ref v)| k == "udp" && v == "true");
        if is_udp {
            return Ok(Transport::Udp(UdpOptions::from_url(url)));
        }

        #[cfg(unix)]
        {
            if url.host().is_none() && url.port() == None {
                return Ok(Transport::Unix);
            }
        }

        Ok(Transport::Tcp(TcpOptions::from_url(url)))
    }
}

fn tcp_stream(url: &Url, opts: &TcpOptions) -> Result<TcpStream, MemcacheError> {
    let tcp_stream = TcpStream::connect(&*url.socket_addrs(|| None)?)?;
    if opts.timeout.is_some() {
        tcp_stream.set_read_timeout(opts.timeout)?;
        tcp_stream.set_write_timeout(opts.timeout)?;
    }
    tcp_stream.set_nodelay(opts.nodelay)?;
    Ok(tcp_stream)
}

impl Connection {
    pub(crate) fn get_url(&self) -> String {
        self.url.to_string()
    }

    pub(crate) fn connect(url: &Url) -> Result<Self, MemcacheError> {
        let transport = Transport::from_url(url)?;
        let is_ascii = url.query_pairs().any(|(ref k, ref v)| k == "protocol" && v == "ascii");
        let stream: Stream = match transport {
            Transport::Tcp(options) => Stream::Tcp(tcp_stream(url, &options)?),
            Transport::Udp(options) => Stream::Udp(UdpStream::new(url, options.bind_addr.as_deref())?),
            #[cfg(unix)]
            Transport::Unix => Stream::Unix(UnixStream::connect(url.path())?),
            #[cfg(all(feature = "tls", not(feature = "rustls")))]
            Transport::Tls(options) => {
                let host = url
                    .host_str()
                    .ok_or(MemcacheError::BadURL("host required for TLS connection".into()))?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;
                builder.set_verify(options.verify_mode);

                if options.ca_path.is_some() {
                    builder.set_ca_file(&options.ca_path.unwrap())?;
                }

                if options.key_path.is_some() {
                    builder.set_private_key_file(options.key_path.unwrap(), SslFiletype::PEM)?;
                }

                if options.cert_path.is_some() {
                    builder.set_certificate_chain_file(options.cert_path.unwrap())?;
                }

                let tls_conn = builder.build();
                let tcp_stream = tcp_stream(url, &options.tcp_options)?;
                let tls_stream = tls_conn.connect(host, tcp_stream)?;
                Stream::Tls(tls_stream)
            }
            #[cfg(feature = "rustls")]
            Transport::Tls(options) => {
                use rustls::pki_types::ServerName;
                use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

                let host = url
                    .host_str()
                    .ok_or(MemcacheError::BadURL("host required for TLS connection".into()))?;

                let tls_config: Arc<ClientConfig> = if options.skip_verify {
                    use rustls::client::danger::{
                        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
                    };
                    use rustls::pki_types::{CertificateDer, UnixTime};
                    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

                    #[derive(Debug)]
                    struct NoVerifier;

                    impl ServerCertVerifier for NoVerifier {
                        fn verify_server_cert(
                            &self,
                            _end_entity: &CertificateDer<'_>,
                            _intermediates: &[CertificateDer<'_>],
                            _server_name: &ServerName<'_>,
                            _ocsp_response: &[u8],
                            _now: UnixTime,
                        ) -> Result<ServerCertVerified, Error> {
                            Ok(ServerCertVerified::assertion())
                        }

                        fn verify_tls12_signature(
                            &self,
                            _message: &[u8],
                            _cert: &CertificateDer<'_>,
                            _dss: &DigitallySignedStruct,
                        ) -> Result<HandshakeSignatureValid, Error> {
                            Ok(HandshakeSignatureValid::assertion())
                        }

                        fn verify_tls13_signature(
                            &self,
                            _message: &[u8],
                            _cert: &CertificateDer<'_>,
                            _dss: &DigitallySignedStruct,
                        ) -> Result<HandshakeSignatureValid, Error> {
                            Ok(HandshakeSignatureValid::assertion())
                        }

                        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                            vec![
                                SignatureScheme::RSA_PKCS1_SHA1,
                                SignatureScheme::ECDSA_SHA1_Legacy,
                                SignatureScheme::RSA_PKCS1_SHA256,
                                SignatureScheme::ECDSA_NISTP256_SHA256,
                                SignatureScheme::RSA_PKCS1_SHA384,
                                SignatureScheme::ECDSA_NISTP384_SHA384,
                                SignatureScheme::RSA_PKCS1_SHA512,
                                SignatureScheme::ECDSA_NISTP521_SHA512,
                                SignatureScheme::RSA_PSS_SHA256,
                                SignatureScheme::RSA_PSS_SHA384,
                                SignatureScheme::RSA_PSS_SHA512,
                                SignatureScheme::ED25519,
                                SignatureScheme::ED448,
                            ]
                        }
                    }

                    Arc::new(
                        ClientConfig::builder()
                            .dangerous()
                            .with_custom_certificate_verifier(Arc::new(NoVerifier))
                            .with_no_client_auth(),
                    )
                } else {
                    let mut root_cert_store = RootCertStore::empty();

                    if let Some(ref ca_path) = options.ca_path {
                        let file = std::fs::File::open(ca_path)?;
                        let mut reader = std::io::BufReader::new(file);
                        for cert in rustls_pemfile::certs(&mut reader) {
                            root_cert_store.add(cert?).map_err(rustls::Error::from)?;
                        }
                    } else {
                        #[cfg(feature = "native-roots")]
                        {
                            let loaded = rustls_native_certs::load_native_certs();
                            for cert in loaded.certs {
                                // Individual cert errors are common (expired/malformed certs in
                                // the system store), so we skip them and continue loading.
                                root_cert_store.add(cert).ok();
                            }
                            if root_cert_store.is_empty() {
                                return Err(MemcacheError::BadURL(
                                    "no usable native root certificates found".into(),
                                ));
                            }
                        }
                        #[cfg(not(feature = "native-roots"))]
                        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    }

                    let config_builder =
                        ClientConfig::builder().with_root_certificates(root_cert_store);

                    if let (Some(key_path), Some(cert_path)) = (options.key_path, options.cert_path) {
                        let cert_file = std::fs::File::open(&cert_path)?;
                        let mut cert_reader = std::io::BufReader::new(cert_file);
                        let certs: Vec<_> =
                            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

                        let key_file = std::fs::File::open(&key_path)?;
                        let mut key_reader = std::io::BufReader::new(key_file);
                        let key = rustls_pemfile::private_key(&mut key_reader)?
                            .ok_or(MemcacheError::BadURL("no private key found in key_path".into()))?;

                        Arc::new(
                            config_builder
                                .with_client_auth_cert(certs, key)
                                .map_err(rustls::Error::from)?,
                        )
                    } else {
                        Arc::new(config_builder.with_no_client_auth())
                    }
                };

                let server_name = ServerName::try_from(host.to_string())
                    .map_err(|_| MemcacheError::BadURL(format!("invalid TLS hostname: {}", host)))?;
                let tcp = tcp_stream(url, &options.tcp_options)?;
                let conn = ClientConnection::new(Arc::clone(&tls_config), server_name)?;
                let tls_stream = StreamOwned::new(conn, tcp);
                Stream::Tls(tls_stream)
            }
        };

        let protocol = if is_ascii {
            Protocol::Ascii(AsciiProtocol::new(stream))
        } else {
            Protocol::Binary(BinaryProtocol { stream: stream })
        };

        Ok(Connection {
            url: Arc::new(url.to_string()),
            protocol: protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn test_transport_url() {
        use super::Transport;
        use url::Url;
        match Transport::from_url(&Url::parse("memcache:///tmp/memcached.sock").unwrap()).unwrap() {
            Transport::Unix => (),
            _ => assert!(false, "transport is not unix"),
        }
    }
}
