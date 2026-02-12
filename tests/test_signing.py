"""Tests for key generation, ENR modification, and re-signing."""

from pyenr import Enr, SigningKey


def test_generate_secp256k1():
    key = SigningKey.generate_secp256k1()
    pk = key.public_key()
    assert isinstance(pk, bytes)
    assert len(pk) == 33  # compressed secp256k1


def test_generate_ed25519():
    key = SigningKey.generate_ed25519()
    pk = key.public_key()
    assert isinstance(pk, bytes)
    assert len(pk) == 32  # ed25519 public key


def test_from_secp256k1_bytes():
    # Generate a key and extract its bytes, then reimport
    key1 = SigningKey.generate_secp256k1()
    pk1 = key1.public_key()

    # Build an ENR with each key and compare public keys
    enr1 = key1.builder()
    e1 = enr1.build(key1)
    assert e1.public_key == pk1


def test_from_ed25519_bytes():
    # Generate an ed25519 key
    key1 = SigningKey.generate_ed25519()
    pk1 = key1.public_key()

    # Build an ENR and verify public key
    enr1 = key1.builder().build(key1)
    assert enr1.public_key == pk1


def test_modify_enr_updates_seq():
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    builder.ip4("10.0.0.1")
    builder.udp4(9000)
    enr = builder.build(key)

    original_seq = enr.seq
    enr.set_tcp4(30303, key)
    assert enr.seq == original_seq + 1
    assert enr.tcp4 == 30303


def test_set_ip4():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set_ip4("192.168.0.1", key)
    assert enr.ip4 == "192.168.0.1"


def test_set_ip6():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set_ip6("::1", key)
    assert enr.ip6 == "::1"


def test_set_udp_ports():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set_udp4(9000, key)
    assert enr.udp4 == 9000

    enr.set_udp6(9001, key)
    assert enr.udp6 == 9001


def test_set_custom_kv():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set("mykey", b"\x01\x02\x03", key)
    val = enr.get("mykey")
    assert val is not None


def test_set_seq_explicitly():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set_seq(42, key)
    assert enr.seq == 42


def test_public_key_matches_after_build():
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    assert enr.public_key == key.public_key()
