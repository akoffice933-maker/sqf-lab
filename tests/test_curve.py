import secrets

import pytest

from sqflab.curve import (
    G,
    N,
    P,
    batch_invert,
    compress,
    decompress,
    hash160,
    is_on_curve,
    p2pkh_address,
    point_add,
    point_neg,
    pubkey_from_private,
    scalar_mult,
    serialize_uncompressed,
    wif,
)


def test_generator_is_on_curve():
    assert is_on_curve(G)
    assert (G[1] * G[1] - G[0] ** 3 - 7) % P == 0


def test_point_add_identity_and_negation():
    assert point_add(None, G) == G
    assert point_add(G, None) == G
    assert point_add(G, point_neg(G)) is None
    assert point_add(G, G) == scalar_mult(2)


def test_scalar_mult_laws():
    k1, k2 = 12345, 67890
    assert point_add(scalar_mult(k1), scalar_mult(k2)) == scalar_mult(k1 + k2)
    assert scalar_mult(k1, scalar_mult(k2)) == scalar_mult(k1 * k2)
    assert scalar_mult(N) is None
    assert scalar_mult(-k1) == point_neg(scalar_mult(k1))


def test_known_vectors_puzzle_one():
    """Bitcoin puzzle #1 is just k = 1; both encodings are public vectors."""
    assert p2pkh_address(compress(G)) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    assert wif(1) == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    assert hash160(compress(G)).hex() == "751e76e8199196d454941c45d1b3a323f1433bd6"


def test_sec1_roundtrip():
    for _ in range(8):
        k = secrets.randbelow(N - 1) + 1
        point = scalar_mult(k)
        assert decompress(compress(point)) == point
        assert decompress(serialize_uncompressed(point)) == point


def test_decompress_rejects_garbage():
    with pytest.raises(ValueError):
        decompress(b"\x02" + (P + 1).to_bytes(32, "big"))
    with pytest.raises(ValueError):
        decompress(b"\x04" + b"\x00" * 64)


def test_batch_invert_matches_pow():
    values = [secrets.randbelow(P - 1) + 1 for _ in range(17)]
    invs = batch_invert(values)
    assert [v * i % P for v, i in zip(values, invs)] == [1] * len(values)


def test_pubkey_from_private_matches_scalar_mult():
    k = 0xDEADBEEF
    assert pubkey_from_private(k) == compress(scalar_mult(k))
