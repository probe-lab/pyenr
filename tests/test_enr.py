"""Tests for decoding and inspecting ENRs."""

import pytest
from pyenr import Enr, SigningKey

# Generate a deterministic test ENR
_KEY = SigningKey.generate_secp256k1()
_BUILDER = _KEY.build_enr()
_BUILDER.ip4("127.0.0.1")
_BUILDER.udp4(30303)
_BUILDER.tcp4(30303)
_TEST_ENR = _BUILDER.build(_KEY)
SAMPLE_ENR = _TEST_ENR.to_base64()


def test_decode_base64():
    enr = Enr.from_base64(SAMPLE_ENR)
    assert enr.seq > 0
    assert len(enr.node_id) == 32


def test_decode_without_prefix():
    raw = SAMPLE_ENR.removeprefix("enr:")
    enr = Enr.from_base64(raw)
    assert len(enr.node_id) == 32


def test_identity_scheme():
    enr = Enr.from_base64(SAMPLE_ENR)
    assert enr.identity_scheme == "v4"


def test_public_key():
    enr = Enr.from_base64(SAMPLE_ENR)
    pk = enr.public_key
    assert isinstance(pk, bytes)
    assert len(pk) == 33  # compressed secp256k1


def test_network_fields():
    enr = Enr.from_base64(SAMPLE_ENR)
    assert enr.ip4 == "127.0.0.1"
    assert enr.udp4 == 30303
    assert enr.tcp4 == 30303


def test_keys_and_items():
    enr = Enr.from_base64(SAMPLE_ENR)
    keys = enr.keys()
    assert "id" in keys
    assert "secp256k1" in keys
    items = enr.items()
    assert len(items) > 0
    for k, v in items:
        assert isinstance(k, str)
        assert isinstance(v, bytes)


def test_str_repr():
    enr = Enr.from_base64(SAMPLE_ENR)
    s = str(enr)
    assert s.startswith("enr:")
    r = repr(enr)
    assert r.startswith("Enr(enr:")


def test_equality():
    a = Enr.from_base64(SAMPLE_ENR)
    b = Enr.from_base64(SAMPLE_ENR)
    assert a == b


def test_hash():
    a = Enr.from_base64(SAMPLE_ENR)
    b = Enr.from_base64(SAMPLE_ENR)
    assert hash(a) == hash(b)
    s = {a, b}
    assert len(s) == 1


def test_invalid_base64():
    with pytest.raises(ValueError):
        Enr.from_base64("not-a-valid-enr")


def test_invalid_bytes():
    with pytest.raises(Exception):
        Enr.from_bytes(b"\x00\x01\x02")


def test_none_fields():
    """An ENR without ip6/tcp6 should return None for those."""
    enr = Enr.from_base64(SAMPLE_ENR)
    assert enr.ip6 is None
    assert enr.tcp6 is None
    assert enr.udp6 is None


def test_get_nonexistent_key():
    enr = Enr.from_base64(SAMPLE_ENR)
    assert enr.get("nonexistent") is None
