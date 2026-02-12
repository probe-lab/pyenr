use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use alloy_rlp::{Decodable, Encodable};
use enr::{CombinedKey, EnrPublicKey};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn to_enr_error<E: std::fmt::Display>(err: E) -> PyErr {
    PyValueError::new_err(err.to_string())
}

/// Python wrapper around `enr::Enr<CombinedKey>`.
#[pyclass(name = "Enr")]
#[derive(Clone)]
struct Enr {
    inner: enr::Enr<CombinedKey>,
}

#[pymethods]
impl Enr {
    /// Decode an ENR from a base64url string (with or without `enr:` prefix).
    #[staticmethod]
    fn from_base64(text: &str) -> PyResult<Self> {
        let inner = enr::Enr::<CombinedKey>::from_str(text).map_err(to_enr_error)?;
        Ok(Enr { inner })
    }

    /// Decode an ENR from raw RLP bytes.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner =
            enr::Enr::<CombinedKey>::decode(&mut &data[..]).map_err(to_enr_error)?;
        Ok(Enr { inner })
    }

    // -- Read accessors --

    #[getter]
    fn seq(&self) -> u64 {
        self.inner.seq()
    }

    #[getter]
    fn node_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.node_id().raw())
    }

    #[getter]
    fn ip4(&self) -> Option<String> {
        self.inner.ip4().map(|ip| ip.to_string())
    }

    #[getter]
    fn ip6(&self) -> Option<String> {
        self.inner.ip6().map(|ip| ip.to_string())
    }

    #[getter]
    fn tcp4(&self) -> Option<u16> {
        self.inner.tcp4()
    }

    #[getter]
    fn tcp6(&self) -> Option<u16> {
        self.inner.tcp6()
    }

    #[getter]
    fn udp4(&self) -> Option<u16> {
        self.inner.udp4()
    }

    #[getter]
    fn udp6(&self) -> Option<u16> {
        self.inner.udp6()
    }

    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let pk = self.inner.public_key();
        PyBytes::new(py, &pk.encode())
    }

    #[getter]
    fn identity_scheme(&self) -> Option<String> {
        self.inner.id()
    }

    // -- Mutation methods --

    fn set_ip4(&mut self, addr: &str, key: &SigningKey) -> PyResult<()> {
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| PyValueError::new_err(e.to_string()))?;
        self.inner
            .set_ip(ip.into(), &key.inner)
            .map_err(to_enr_error)?;
        Ok(())
    }

    fn set_ip6(&mut self, addr: &str, key: &SigningKey) -> PyResult<()> {
        let ip: Ipv6Addr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| PyValueError::new_err(e.to_string()))?;
        self.inner
            .set_ip(ip.into(), &key.inner)
            .map_err(to_enr_error)?;
        Ok(())
    }

    fn set_tcp4(&mut self, port: u16, key: &SigningKey) -> PyResult<()> {
        self.inner
            .set_tcp4(port, &key.inner)
            .map_err(to_enr_error)?;
        Ok(())
    }

    fn set_tcp6(&mut self, port: u16, key: &SigningKey) -> PyResult<()> {
        self.inner
            .insert("tcp6", &port, &key.inner)
            .map_err(to_enr_error)?;
        Ok(())
    }

    fn set_udp4(&mut self, port: u16, key: &SigningKey) -> PyResult<()> {
        self.inner
            .set_udp4(port, &key.inner)
            .map_err(to_enr_error)?;
        Ok(())
    }

    fn set_udp6(&mut self, port: u16, key: &SigningKey) -> PyResult<()> {
        self.inner
            .insert("udp6", &port, &key.inner)
            .map_err(to_enr_error)?;
        Ok(())
    }

    fn set_seq(&mut self, seq: u64, key: &SigningKey) -> PyResult<()> {
        self.inner
            .set_seq(seq, &key.inner)
            .map_err(to_enr_error)?;
        Ok(())
    }

    /// Set an arbitrary key-value pair.
    #[pyo3(name = "set")]
    fn set_kv(&mut self, key: &str, value: &[u8], signing_key: &SigningKey) -> PyResult<()> {
        self.inner
            .insert(key, &value.to_vec(), &signing_key.inner)
            .map_err(to_enr_error)?;
        Ok(())
    }

    /// Get an arbitrary key-value pair.
    fn get<'py>(&self, py: Python<'py>, key: &str) -> Option<Bound<'py, PyBytes>> {
        #[allow(deprecated)]
        self.inner.get(key).map(|v| PyBytes::new(py, &v))
    }

    // -- Serialization --

    fn to_base64(&self) -> String {
        self.inner.to_base64()
    }

    #[pyo3(name = "to_bytes")]
    fn to_bytes_py<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let mut buf = Vec::new();
        self.inner.encode(&mut buf);
        PyBytes::new(py, &buf)
    }

    fn __str__(&self) -> String {
        self.inner.to_base64()
    }

    fn __repr__(&self) -> String {
        format!("Enr({})", self.inner.to_base64())
    }

    // -- Iteration --

    fn keys(&self) -> Vec<String> {
        self.inner
            .iter()
            .map(|(k, _)| String::from_utf8_lossy(k).to_string())
            .collect()
    }

    fn items<'py>(&self, py: Python<'py>) -> Vec<(String, Bound<'py, PyBytes>)> {
        self.inner
            .iter()
            .map(|(k, v)| {
                (
                    String::from_utf8_lossy(k).to_string(),
                    PyBytes::new(py, v),
                )
            })
            .collect()
    }

    // -- Comparison --

    fn __eq__(&self, other: &Enr) -> bool {
        let mut a = Vec::new();
        let mut b = Vec::new();
        self.inner.encode(&mut a);
        other.inner.encode(&mut b);
        a == b
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut buf = Vec::new();
        self.inner.encode(&mut buf);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        buf.hash(&mut hasher);
        hasher.finish()
    }
}

/// Python wrapper around `CombinedKey`.
#[pyclass(name = "SigningKey")]
struct SigningKey {
    inner: CombinedKey,
}

#[pymethods]
impl SigningKey {
    #[staticmethod]
    fn from_secp256k1(secret: &[u8]) -> PyResult<Self> {
        let mut bytes = secret.to_vec();
        let key = CombinedKey::secp256k1_from_bytes(&mut bytes).map_err(to_enr_error)?;
        Ok(SigningKey { inner: key })
    }

    #[staticmethod]
    fn from_ed25519(secret: &[u8]) -> PyResult<Self> {
        let mut bytes = secret.to_vec();
        let key = CombinedKey::ed25519_from_bytes(&mut bytes).map_err(to_enr_error)?;
        Ok(SigningKey { inner: key })
    }

    #[staticmethod]
    fn generate_secp256k1() -> Self {
        SigningKey {
            inner: CombinedKey::generate_secp256k1(),
        }
    }

    #[staticmethod]
    fn generate_ed25519() -> Self {
        SigningKey {
            inner: CombinedKey::generate_ed25519(),
        }
    }

    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        use enr::EnrKey;
        let pk = self.inner.public();
        PyBytes::new(py, &pk.encode())
    }

    fn builder(&self) -> EnrBuilder {
        EnrBuilder {
            builder: InnerBuilder::new(),
        }
    }
}

/// Internal builder state.
struct InnerBuilder {
    ip4: Option<Ipv4Addr>,
    ip6: Option<Ipv6Addr>,
    tcp4: Option<u16>,
    tcp6: Option<u16>,
    udp4: Option<u16>,
    udp6: Option<u16>,
    custom: Vec<(String, Vec<u8>)>,
}

impl InnerBuilder {
    fn new() -> Self {
        InnerBuilder {
            ip4: None,
            ip6: None,
            tcp4: None,
            tcp6: None,
            udp4: None,
            udp6: None,
            custom: Vec::new(),
        }
    }
}

/// Builder pattern for creating new ENRs from scratch.
#[pyclass(name = "EnrBuilder")]
struct EnrBuilder {
    builder: InnerBuilder,
}

#[pymethods]
impl EnrBuilder {
    fn ip4(&mut self, addr: &str) -> PyResult<()> {
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| PyValueError::new_err(e.to_string()))?;
        self.builder.ip4 = Some(ip);
        Ok(())
    }

    fn ip6(&mut self, addr: &str) -> PyResult<()> {
        let ip: Ipv6Addr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| PyValueError::new_err(e.to_string()))?;
        self.builder.ip6 = Some(ip);
        Ok(())
    }

    fn tcp4(&mut self, port: u16) {
        self.builder.tcp4 = Some(port);
    }

    fn tcp6(&mut self, port: u16) {
        self.builder.tcp6 = Some(port);
    }

    fn udp4(&mut self, port: u16) {
        self.builder.udp4 = Some(port);
    }

    fn udp6(&mut self, port: u16) {
        self.builder.udp6 = Some(port);
    }

    fn add(&mut self, key: &str, value: &[u8]) {
        self.builder.custom.push((key.to_string(), value.to_vec()));
    }

    fn build(&self, key: &SigningKey) -> PyResult<Enr> {
        let mut builder = enr::Enr::builder();
        if let Some(ip) = self.builder.ip4 {
            builder.ip4(ip);
        }
        if let Some(ip) = self.builder.ip6 {
            builder.ip6(ip);
        }
        if let Some(port) = self.builder.tcp4 {
            builder.tcp4(port);
        }
        if let Some(port) = self.builder.tcp6 {
            builder.tcp6(port);
        }
        if let Some(port) = self.builder.udp4 {
            builder.udp4(port);
        }
        if let Some(port) = self.builder.udp6 {
            builder.udp6(port);
        }
        for (k, v) in &self.builder.custom {
            builder.add_value(k, &v.clone());
        }
        let inner = builder.build(&key.inner).map_err(to_enr_error)?;
        Ok(Enr { inner })
    }
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Enr>()?;
    m.add_class::<SigningKey>()?;
    m.add_class::<EnrBuilder>()?;
    Ok(())
}
