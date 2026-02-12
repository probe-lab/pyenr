"""Roundtrip encode/decode tests."""

from pyenr import Enr, SigningKey


def test_base64_roundtrip():
    key = SigningKey.generate_secp256k1()
    builder = key.build_enr()
    builder.ip4("127.0.0.1")
    builder.tcp4(30303)
    builder.udp4(30303)
    enr = builder.build(key)

    encoded = enr.to_base64()
    decoded = Enr.from_base64(encoded)
    assert decoded == enr
    assert decoded.ip4 == "127.0.0.1"
    assert decoded.tcp4 == 30303
    assert decoded.udp4 == 30303


def test_bytes_roundtrip():
    key = SigningKey.generate_secp256k1()
    builder = key.build_enr()
    builder.ip4("10.0.0.1")
    builder.udp4(9000)
    enr = builder.build(key)

    raw = enr.to_bytes()
    decoded = Enr.from_bytes(raw)
    assert decoded == enr
    assert decoded.ip4 == "10.0.0.1"
    assert decoded.udp4 == 9000


def test_ed25519_roundtrip():
    key = SigningKey.generate_ed25519()
    builder = key.build_enr()
    builder.ip4("192.168.1.1")
    builder.tcp4(8545)
    enr = builder.build(key)

    encoded = enr.to_base64()
    decoded = Enr.from_base64(encoded)
    assert decoded == enr
    assert decoded.ip4 == "192.168.1.1"
    assert decoded.tcp4 == 8545


def test_decode_known_enr():
    """Build an ENR, encode it, decode it back, and verify equality."""
    key = SigningKey.generate_secp256k1()
    builder = key.build_enr()
    builder.ip4("10.0.0.1")
    builder.tcp4(30303)
    builder.udp4(9000)
    original = builder.build(key)

    encoded = original.to_base64()
    decoded = Enr.from_base64(encoded)
    roundtripped = Enr.from_base64(decoded.to_base64())
    assert roundtripped == original
