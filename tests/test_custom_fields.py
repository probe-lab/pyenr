"""Tests for custom key-value pair handling."""

from pyenr import Enr, SigningKey


def test_overwrite_custom_field():
    """Setting the same custom key twice should update the value."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set("mykey", b"\x01", key)
    val1 = enr.get("mykey")
    assert val1 is not None

    enr.set("mykey", b"\x02", key)
    val2 = enr.get("mykey")
    assert val2 is not None
    assert val2 != val1


def test_many_custom_fields():
    """ENR with many custom fields should work correctly."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    for i in range(20):
        enr.set(f"key{i}", bytes([i]), key)

    for i in range(20):
        val = enr.get(f"key{i}")
        assert val is not None


def test_custom_field_empty_value():
    """Custom field with empty bytes value."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set("empty", b"", key)
    val = enr.get("empty")
    assert val is not None


def test_custom_field_large_value_rejected():
    """A value exceeding the ENR max size (300 bytes) should be rejected."""
    import pytest

    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    data = bytes(range(256)) * 2  # 512 bytes — exceeds 300 byte limit
    with pytest.raises(ValueError, match="max size"):
        enr.set("big", data, key)


def test_custom_field_survives_roundtrip():
    """Custom key-value pairs should survive base64 encode/decode."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set("foo", b"\xca\xfe", key)
    encoded = enr.to_base64()
    decoded = Enr.from_base64(encoded)

    assert decoded.get("foo") is not None


def test_custom_field_survives_bytes_roundtrip():
    """Custom key-value pairs should survive bytes encode/decode."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set("bar", b"\xde\xad", key)
    raw = enr.to_bytes()
    decoded = Enr.from_bytes(raw)

    assert decoded.get("bar") is not None


def test_custom_field_in_keys_and_items():
    """Custom fields should appear in keys() and items()."""
    key = SigningKey.generate_secp256k1()
    enr = key.builder().build(key)

    enr.set("custom1", b"\x01", key)
    assert "custom1" in enr.keys()

    found = False
    for k, v in enr.items():
        if k == "custom1":
            found = True
            break
    assert found


def test_builder_custom_field():
    """Custom fields added via builder should be accessible."""
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    builder.add("builtin", b"\x01\x02\x03")
    enr = builder.build(key)

    assert enr.get("builtin") is not None
    assert "builtin" in enr.keys()


def test_builder_multiple_custom_fields():
    """Multiple custom fields added via builder."""
    key = SigningKey.generate_secp256k1()
    builder = key.builder()
    builder.add("field_a", b"\x0a")
    builder.add("field_b", b"\x0b")
    builder.add("field_c", b"\x0c")
    enr = builder.build(key)

    assert enr.get("field_a") is not None
    assert enr.get("field_b") is not None
    assert enr.get("field_c") is not None
