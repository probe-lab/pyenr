"""Tests for input validation and error handling."""

import pytest
from pyenr import Enr, SigningKey


# -- Invalid IP addresses --


def test_builder_invalid_ipv4():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    with pytest.raises(ValueError):
        builder.ip4("256.1.1.1")


def test_builder_invalid_ipv4_text():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    with pytest.raises(ValueError):
        builder.ip4("not-an-ip")


def test_builder_invalid_ipv4_empty():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    with pytest.raises(ValueError):
        builder.ip4("")


def test_builder_invalid_ipv6():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    with pytest.raises(ValueError):
        builder.ip6("not-an-ipv6")


def test_set_invalid_ipv4():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    with pytest.raises(ValueError):
        enr.set_ip4("999.999.999.999", key)


def test_set_invalid_ipv6():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    with pytest.raises(ValueError):
        enr.set_ip6("zzzz::1", key)


# -- Invalid port numbers --


def test_builder_port_too_large():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    with pytest.raises(OverflowError):
        builder.tcp4(70000)


def test_builder_port_negative():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    with pytest.raises(OverflowError):
        builder.udp4(-1)


def test_set_port_too_large():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    with pytest.raises(OverflowError):
        enr.set_tcp4(70000, key)


def test_set_port_negative():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    with pytest.raises(OverflowError):
        enr.set_udp4(-1, key)


# -- Invalid key sizes --


def test_invalid_secp256k1_key_too_short():
    with pytest.raises(ValueError):
        SigningKey.from_secp256k1(b"\x01" * 16)


def test_invalid_secp256k1_key_too_long():
    with pytest.raises(ValueError):
        SigningKey.from_secp256k1(b"\x01" * 64)


def test_invalid_secp256k1_key_empty():
    with pytest.raises(ValueError):
        SigningKey.from_secp256k1(b"")


def test_invalid_ed25519_key_too_short():
    with pytest.raises(ValueError):
        SigningKey.from_ed25519(b"\x01" * 16)


def test_invalid_ed25519_key_too_long():
    with pytest.raises(ValueError):
        SigningKey.from_ed25519(b"\x01" * 64)


def test_invalid_ed25519_key_empty():
    with pytest.raises(ValueError):
        SigningKey.from_ed25519(b"")


# -- Invalid ENR data --


def test_from_base64_empty():
    with pytest.raises(ValueError):
        Enr.from_base64("")


def test_from_base64_garbage():
    with pytest.raises(ValueError):
        Enr.from_base64("this-is-not-an-enr-at-all")


def test_from_base64_truncated():
    """A truncated base64 ENR should fail to decode."""
    valid = (
        "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04j"
        "RzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2Vj"
    )
    # Truncate to make it invalid
    with pytest.raises(ValueError):
        Enr.from_base64(valid[:30])


def test_from_bytes_empty():
    with pytest.raises(Exception):
        Enr.from_bytes(b"")


def test_from_bytes_single_byte():
    with pytest.raises(Exception):
        Enr.from_bytes(b"\xff")
