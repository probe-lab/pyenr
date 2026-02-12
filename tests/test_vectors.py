"""Test vectors from the sigp/enr crate and EIP-778 for interoperability."""

from pyenr import Enr, SigningKey


# EIP-778 canonical test vector
EIP778_PRIVATE_KEY = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
EIP778_PUBLIC_KEY = "03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138"
EIP778_NODE_ID = "a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
EIP778_BASE64 = (
    "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04j"
    "RzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2Vj"
    "cDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCC"
    "dl8"
)
EIP778_RLP_HEX = (
    "f884b8407098ad865b00a582051940cb9cf36836572411a47278783077011599"
    "ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1"
    "145ccb9c01826964827634826970847f00000189736563703235366b31a103ca"
    "634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd313883"
    "75647082765f"
)


def test_vector_base64():
    """Decode the EIP-778 canonical base64 ENR and verify fields."""
    enr = Enr.from_base64(EIP778_BASE64)
    assert enr.public_key.hex() == EIP778_PUBLIC_KEY
    assert enr.node_id.hex() == EIP778_NODE_ID
    assert enr.ip4 == "127.0.0.1"
    assert enr.udp4 == 30303
    assert enr.tcp4 is None
    assert enr.seq == 1
    assert enr.identity_scheme == "v4"


def test_vector_rlp():
    """Decode the EIP-778 canonical RLP bytes and verify fields."""
    enr = Enr.from_bytes(bytes.fromhex(EIP778_RLP_HEX))
    assert enr.public_key.hex() == EIP778_PUBLIC_KEY
    assert enr.node_id.hex() == EIP778_NODE_ID
    assert enr.ip4 == "127.0.0.1"
    assert enr.udp4 == 30303
    assert enr.seq == 1


def test_vector_base64_and_rlp_match():
    """The base64 and RLP decodings produce the same ENR."""
    enr_b64 = Enr.from_base64(EIP778_BASE64)
    enr_rlp = Enr.from_bytes(bytes.fromhex(EIP778_RLP_HEX))
    assert enr_b64 == enr_rlp


def test_vector_from_private_key():
    """Build an ENR from the known private key and verify node_id."""
    key = SigningKey.from_secp256k1(bytes.fromhex(EIP778_PRIVATE_KEY))
    assert key.public_key().hex() == EIP778_PUBLIC_KEY
    builder = key.builder()
    builder.ip4("127.0.0.1")
    builder.udp4(30303)
    enr = builder.build(key)
    assert enr.node_id.hex() == EIP778_NODE_ID
    assert enr.ip4 == "127.0.0.1"
    assert enr.udp4 == 30303


def test_enr_without_prefix():
    """Decode a base64 ENR without the enr: prefix."""
    raw = EIP778_BASE64.removeprefix("enr:")
    enr = Enr.from_base64(raw)
    assert enr.node_id.hex() == EIP778_NODE_ID


def test_enr_with_and_without_prefix_equal():
    """Decoding with or without enr: prefix gives the same ENR."""
    raw = EIP778_BASE64.removeprefix("enr:")
    enr_no_prefix = Enr.from_base64(raw)
    enr_with_prefix = Enr.from_base64(EIP778_BASE64)
    assert enr_no_prefix == enr_with_prefix


def test_low_integer_port_valid():
    """Verify an ENR with tcp4=30303 decodes correctly."""
    enr = Enr.from_base64(
        "enr:-Hy4QF_mn4BuM6hY4CuLH8xDQd7U8kVZe9fyNgRB1vjdToGWQsQhe"
        "tRvsByoJCWGQ6kf2aiWC0le24lkp0IPIJkLSTUBgmlkgnY0iXNlY3AyNTZr"
        "MaECMoYV0PAXMueQz19FHpBO0jGBoLYCWhfSxGf5kQgk9KqDdGNwgnZf"
    )
    assert enr.tcp4 == 30303
