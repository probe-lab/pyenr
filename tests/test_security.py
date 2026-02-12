"""Tests for signing key behavior and signature integrity."""

from pyenr import Enr, SigningKey


def test_modify_with_different_key_changes_public_key():
    """Modifying an ENR with a different key re-signs it with the new key."""
    key1 = SigningKey.generate_secp256k1()
    key2 = SigningKey.generate_secp256k1()

    enr = key1.builder().build(key1)
    assert enr.public_key == key1.public_key()

    enr.set_ip4("10.0.0.1", key2)
    assert enr.public_key == key2.public_key()
    assert enr.public_key != key1.public_key()


def test_modified_enr_signature_valid_after_roundtrip():
    """An ENR modified and re-signed should survive encode/decode."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    enr.set_ip4("10.0.0.1", key)
    enr.set_tcp4(30303, key)

    encoded = enr.to_base64()
    decoded = Enr.from_base64(encoded)
    assert decoded == enr
    assert decoded.ip4 == "10.0.0.1"
    assert decoded.tcp4 == 30303


def test_modified_enr_bytes_roundtrip():
    """An ENR modified and re-signed should survive bytes encode/decode."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    enr.set_udp4(9000, key)

    raw = enr.to_bytes()
    decoded = Enr.from_bytes(raw)
    assert decoded == enr
    assert decoded.udp4 == 9000


def test_different_keys_produce_different_node_ids():
    """Two different keys should produce ENRs with different node IDs."""
    key1 = SigningKey.generate_secp256k1()
    key2 = SigningKey.generate_secp256k1()

    enr1 = key1.builder().build(key1)
    enr2 = key2.builder().build(key2)

    assert enr1.node_id != enr2.node_id
    assert enr1.public_key != enr2.public_key


def test_same_key_deterministic_node_id():
    """The same key should always produce the same node ID."""
    secret = b"\xab" * 32
    key1 = SigningKey.from_secp256k1(secret)
    key2 = SigningKey.from_secp256k1(secret)

    enr1 = key1.builder().build(key1)
    enr2 = key2.builder().build(key2)

    assert enr1.node_id == enr2.node_id
    assert enr1.public_key == enr2.public_key


def test_ed25519_different_keys_different_node_ids():
    """Two different ed25519 keys should produce different node IDs."""
    key1 = SigningKey.generate_ed25519()
    key2 = SigningKey.generate_ed25519()

    enr1 = key1.builder().build(key1)
    enr2 = key2.builder().build(key2)

    assert enr1.node_id != enr2.node_id


def test_re_signing_preserves_fields():
    """Re-signing with a different key preserves existing fields."""
    key1 = SigningKey.generate_secp256k1()
    key2 = SigningKey.generate_secp256k1()

    builder = key1.builder()
    builder.ip4("192.168.1.1")
    builder.tcp4(30303)
    builder.udp4(9000)
    enr = builder.build(key1)

    # Modify with key2 — re-signs the record
    enr.set_ip4("10.0.0.1", key2)

    # ip4 changed, other fields preserved
    assert enr.ip4 == "10.0.0.1"
    assert enr.tcp4 == 30303
    assert enr.udp4 == 9000
    assert enr.public_key == key2.public_key()
