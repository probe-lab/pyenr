"""Tests for the EnrBuilder API."""

from pyenr import SigningKey


def test_builder_minimal():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    assert enr.seq == 1
    assert enr.ip4 is None
    assert enr.tcp4 is None
    assert enr.udp4 is None


def test_builder_with_ip4():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    builder.ip4("10.0.0.1")
    enr = builder.build(key)
    assert enr.ip4 == "10.0.0.1"


def test_builder_with_all_fields():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    builder.ip4("192.168.1.1")
    builder.ip6("::1")
    builder.tcp4(30303)
    builder.tcp6(30304)
    builder.udp4(9000)
    builder.udp6(9001)
    enr = builder.build(key)

    assert enr.ip4 == "192.168.1.1"
    assert enr.ip6 == "::1"
    assert enr.tcp4 == 30303
    assert enr.tcp6 == 30304
    assert enr.udp4 == 9000
    assert enr.udp6 == 9001


def test_builder_with_custom_kv():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    builder.add("myfield", b"\xde\xad\xbe\xef")
    enr = builder.build(key)
    val = enr.get("myfield")
    assert val is not None


def test_builder_ed25519():
    key = SigningKey.generate_ed25519()
    builder = key.builder()
    builder.ip4("127.0.0.1")
    builder.udp4(30303)
    enr = builder.build(key)
    assert enr.ip4 == "127.0.0.1"
    assert enr.udp4 == 30303
    assert enr.identity_scheme == "v4"
