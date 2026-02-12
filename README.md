# pyenr

A Python library for encoding, decoding, and modifying [Ethereum Node Records](https://eips.ethereum.org/EIPS/eip-778) (ENR, EIP-778). Built on Rust via [PyO3](https://pyo3.rs) for performance and correctness, wrapping the battle-tested [`enr`](https://github.com/sigp/enr) crate from Sigma Prime (used in [Lighthouse](https://github.com/sigp/lighthouse)).

## Features

- Decode ENRs from base64 strings or raw RLP bytes
- Create new ENRs with the builder pattern
- Modify existing ENRs (IP, ports, custom key-value pairs) with automatic re-signing
- Support for both **secp256k1** and **ed25519** identity schemes
- Full type stubs for IDE autocomplete and type checking
- Requires Python 3.9 – 3.14

## Installation

pyenr is built with [Maturin](https://github.com/PyO3/maturin). You need a Rust toolchain installed.

```bash
# Install from source
pip install .

# Or for development
pip install maturin
maturin develop
```

With [uv](https://docs.astral.sh/uv/):

```bash
uv run maturin develop
```

## Quick Start

### Decode an ENR

```python
from pyenr import Enr

enr = Enr.from_base64("enr:-IS4QHCYrYZbAK...")

print(enr.node_id.hex())    # 32-byte node ID
print(enr.seq)              # sequence number
print(enr.ip4)              # "127.0.0.1" or None
print(enr.udp4)             # 30303 or None
print(enr.identity_scheme)  # "v4"
print(enr.public_key.hex()) # compressed public key
```

### Create a new ENR

```python
from pyenr import SigningKey

key = SigningKey.generate_secp256k1()

builder = key.builder()
builder.ip4("192.168.1.1")
builder.tcp4(30303)
builder.udp4(9000)

enr = builder.build(key)
print(enr)  # enr:-IS4Q...
```

### Modify an existing ENR

All mutations require the signing key and automatically increment the sequence number and re-sign the record.

```python
enr.set_ip4("10.0.0.1", key)
enr.set_tcp4(8545, key)
enr.set_seq(100, key)

# Arbitrary key-value pairs
enr.set("mykey", b"\x01\x02\x03", key)
value = enr.get("mykey")  # bytes or None
```

### Use ed25519 keys

```python
key = SigningKey.generate_ed25519()
enr = key.builder().build(key)
```

### Import an existing key

```python
secret = bytes.fromhex("ab" * 32)
key = SigningKey.from_secp256k1(secret)
# or
key = SigningKey.from_ed25519(secret)
```

### Serialize

```python
base64_str = enr.to_base64()  # "enr:-IS4Q..."
raw_bytes = enr.to_bytes()    # RLP-encoded bytes

# Decode back
enr2 = Enr.from_base64(base64_str)
enr3 = Enr.from_bytes(raw_bytes)
assert enr2 == enr3
```

### Inspect all fields

```python
enr.keys()   # ["id", "ip", "secp256k1", "tcp", "udp"]
enr.items()  # [("id", b"..."), ("ip", b"..."), ...]
```

## API Reference

### `Enr`

| Constructor | Description |
|---|---|
| `Enr.from_base64(text)` | Decode from base64url string (with or without `enr:` prefix) |
| `Enr.from_bytes(data)` | Decode from raw RLP bytes |

| Property | Type | Description |
|---|---|---|
| `seq` | `int` | Sequence number |
| `node_id` | `bytes` | 32-byte node ID |
| `ip4` | `str \| None` | IPv4 address |
| `ip6` | `str \| None` | IPv6 address |
| `tcp4` | `int \| None` | TCP port (IPv4) |
| `tcp6` | `int \| None` | TCP port (IPv6) |
| `udp4` | `int \| None` | UDP port (IPv4) |
| `udp6` | `int \| None` | UDP port (IPv6) |
| `public_key` | `bytes` | Compressed public key |
| `identity_scheme` | `str \| None` | Identity scheme (e.g. `"v4"`) |

| Method | Description |
|---|---|
| `set_ip4(addr, key)` | Set IPv4 address |
| `set_ip6(addr, key)` | Set IPv6 address |
| `set_tcp4(port, key)` | Set TCP port (IPv4) |
| `set_tcp6(port, key)` | Set TCP port (IPv6) |
| `set_udp4(port, key)` | Set UDP port (IPv4) |
| `set_udp6(port, key)` | Set UDP port (IPv6) |
| `set_seq(seq, key)` | Set sequence number |
| `set(key, value, signing_key)` | Set arbitrary key-value pair |
| `get(key)` | Get value for key (`bytes \| None`) |
| `to_base64()` | Encode to base64url string with `enr:` prefix |
| `to_bytes()` | Encode to RLP bytes |
| `keys()` | List all keys |
| `items()` | List all key-value pairs |

### `SigningKey`

| Constructor | Description |
|---|---|
| `SigningKey.from_secp256k1(secret)` | Import from 32-byte secp256k1 secret |
| `SigningKey.from_ed25519(secret)` | Import from 32-byte ed25519 secret |
| `SigningKey.generate_secp256k1()` | Generate random secp256k1 key |
| `SigningKey.generate_ed25519()` | Generate random ed25519 key |

| Method | Description |
|---|---|
| `public_key()` | Get compressed public key bytes |
| `builder()` | Start building a new ENR |

### `EnrBuilder`

| Method | Description |
|---|---|
| `ip4(addr)` | Set IPv4 address |
| `ip6(addr)` | Set IPv6 address |
| `tcp4(port)` | Set TCP port (IPv4) |
| `tcp6(port)` | Set TCP port (IPv6) |
| `udp4(port)` | Set UDP port (IPv4) |
| `udp6(port)` | Set UDP port (IPv6) |
| `add(key, value)` | Add custom key-value pair |
| `build(key)` | Sign and return the ENR |

## Development

### Prerequisites

- Python 3.9 – 3.14
- Rust toolchain (install via [rustup](https://rustup.rs))
- [uv](https://docs.astral.sh/uv/) (recommended) or pip + maturin

### Build and test

```bash
# Build the extension in development mode
uv run maturin develop

# Run Python tests
uv run pytest tests/ -v

# Check Rust compilation
cargo check
```

## License

MIT
