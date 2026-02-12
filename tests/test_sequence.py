"""Tests for sequence number behavior."""

from pyenr import SigningKey


def test_new_enr_starts_at_seq_1():
    """A freshly built ENR should have seq=1."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    assert enr.seq == 1


def test_sequential_modifications_increment_seq():
    """Each modification should increment the sequence number."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    assert enr.seq == 1

    enr.set_ip4("10.0.0.1", key)
    assert enr.seq == 2

    enr.set_tcp4(30303, key)
    assert enr.seq == 3

    enr.set_udp4(9000, key)
    assert enr.seq == 4

    enr.set_ip6("::1", key)
    assert enr.seq == 5


def test_multiple_set_increments():
    """Setting the same field multiple times keeps incrementing."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    for i in range(5):
        enr.set_ip4(f"10.0.0.{i + 1}", key)
        assert enr.seq == i + 2  # starts at 1, first set makes it 2


def test_set_seq_explicitly():
    """Setting seq explicitly should work."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set_seq(100, key)
    assert enr.seq == 100


def test_set_seq_to_lower_value():
    """Setting seq to a lower value should still work."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set_seq(100, key)
    assert enr.seq == 100

    enr.set_seq(50, key)
    assert enr.seq == 50


def test_set_seq_to_zero():
    """Setting seq to 0 should work (valid per EIP-778)."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set_seq(0, key)
    assert enr.seq == 0


def test_set_custom_kv_increments_seq():
    """Setting a custom key-value pair should also increment seq."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)
    assert enr.seq == 1

    enr.set("mykey", b"\x01", key)
    assert enr.seq == 2


def test_seq_preserved_after_roundtrip():
    """Sequence number should survive encode/decode."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set_seq(42, key)

    from pyenr import Enr
    decoded = Enr.from_base64(enr.to_base64())
    assert decoded.seq == 42
