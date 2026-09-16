//! Per-test configuration copies; checked-in fixtures and trust stores stay untouched.

use std::{
    fs, io,
    panic::UnwindSafe,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use super::{named_test_harness_with_config, SocketPorts};

pub struct TestConfig {
    directory: PathBuf,
    value: toml::Value,
}

impl TestConfig {
    fn new(template: &str) -> Self {
        let root = std::env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".into());
        let template = PathBuf::from(root)
            .join("tests/test-data/test_configs")
            .join(template);
        let value = fs::read_to_string(template).unwrap().parse().unwrap();
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let directory = std::env::temp_dir().join(format!(
                "hickory-startup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&directory) {
                Ok(()) => return Self { directory, value },
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create startup fixture directory: {error}"),
            }
        }
    }

    pub fn run<F, R>(&self, test: F)
    where
        F: FnOnce(SocketPorts) -> R + UnwindSafe,
    {
        let path = self.directory.join("config.toml");
        fs::write(&path, toml::to_string(&self.value).unwrap()).unwrap();
        named_test_harness_with_config(&path, test);
    }

    #[cfg(feature = "resolver")]
    pub fn forwarder(upstream: &SocketPorts) -> Self {
        use hickory_proto::xfer::Protocol;
        let mut config = Self::new("example_forwarder.toml");
        let zones = config.value["zones"].as_array_mut().unwrap();
        let zone = zones
            .iter_mut()
            .find(|zone| zone["zone_type"].as_str() == Some("Forward"))
            .unwrap();
        let servers = zone["stores"]["name_servers"].as_array_mut().unwrap();
        assert_eq!(servers.len(), 2);
        for server in servers {
            let protocol = match server["protocol"].as_str().unwrap() {
                "udp" => Protocol::Udp,
                "tcp" => Protocol::Tcp,
                other => panic!("unexpected forwarding protocol: {other}"),
            };
            let port = upstream.get_v4(protocol).unwrap();
            server["socket_addr"] = format!("127.0.0.1:{port}").into();
        }
        config
    }
}

impl Drop for TestConfig {
    fn drop(&mut self) {
        // This directory was exclusively created by this instance, never reused.
        if let Err(error) = fs::remove_dir_all(&self.directory) {
            if !std::thread::panicking() {
                panic!("cannot remove startup fixture directory: {error}");
            }
        }
    }
}

#[test]
fn failed_startup_cleans_fixture() {
    let mut config = TestConfig::new("example.toml");
    let directory = config.directory.clone();
    config
        .value
        .as_table_mut()
        .unwrap()
        .insert("listen_addrs_ipv4".into(), "invalid address array".into());
    let invoked = std::sync::atomic::AtomicBool::new(false);
    let result = std::panic::catch_unwind(|| {
        config.run(|_| invoked.store(true, Ordering::Relaxed));
    });
    assert!(result.is_err());
    assert!(!invoked.load(Ordering::Relaxed));
    drop(config);
    assert!(!directory.exists());
}

#[test]
fn failed_callback_cleans_fixture() {
    let config = TestConfig::new("example.toml");
    let directory = config.directory.clone();
    let invoked = std::sync::atomic::AtomicBool::new(false);
    let result = std::panic::catch_unwind(|| {
        config.run(|_| {
            invoked.store(true, Ordering::Relaxed);
            panic!("intentional callback failure");
        });
    });
    assert!(result.is_err());
    assert!(invoked.load(Ordering::Relaxed));
    drop(config);
    assert!(!directory.exists());
}

#[cfg(feature = "dns-over-tls")]
pub struct TlsConfig {
    config: TestConfig,
    pub root_der: Vec<u8>,
}

#[cfg(feature = "dns-over-tls")]
impl TlsConfig {
    pub fn new(template: &str) -> Self {
        let mut config = TestConfig::new(template);
        let identity = test_support::tls::TestIdentity::new("ns.example.com").unwrap();
        let tls = config.value["tls_cert"].as_table_mut().unwrap();
        if tls.get("cert_type").and_then(toml::Value::as_str) == Some("pem") {
            let cert = config.directory.join("cert.pem");
            let key = config.directory.join("key.der");
            fs::write(&cert, identity.cert.to_pem().unwrap()).unwrap();
            fs::write(&key, identity.key.private_key_to_der().unwrap()).unwrap();
            tls.insert("path".into(), cert.to_str().unwrap().into());
            tls.insert("private_key".into(), key.to_str().unwrap().into());
        } else {
            #[cfg(feature = "dns-over-openssl")]
            {
                let password = tls
                    .get("password")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("");
                let archive = openssl::pkcs12::Pkcs12::builder()
                    .name("startup fixture")
                    .pkey(&identity.key)
                    .cert(&identity.cert)
                    .build2(password)
                    .unwrap();
                let path = config.directory.join("identity.p12");
                fs::write(&path, archive.to_der().unwrap()).unwrap();
                tls.insert("path".into(), path.to_str().unwrap().into());
            }
            #[cfg(not(feature = "dns-over-openssl"))]
            panic!("PKCS12 fixture requires the OpenSSL backend");
        }
        Self {
            config,
            root_der: identity.ca.to_der().unwrap(),
        }
    }

    #[cfg(feature = "dns-over-rustls")]
    pub fn client_config(&self) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                self.root_der.clone(),
            ))
            .unwrap();
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
    }

    pub fn run<F, R>(&self, test: F)
    where
        F: FnOnce(SocketPorts) -> R + UnwindSafe,
    {
        self.config.run(test);
    }
}
