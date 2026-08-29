"""Unit coverage for the hashing primitives, independent of the vectors."""

import hashlib
import json

import pytest

from shim_audit_verify.hashing import (
    canonical_row,
    chain_hash,
    compute_row_hash,
    genesis_hash,
    merkle_root,
)


def test_canonical_row_sorts_keys_at_every_depth() -> None:
    unsorted = {"b": 1, "a": {"z": 1, "y": 2}}
    assert canonical_row(unsorted) == b'{"a":{"y":2,"z":1},"b":1}'


def test_canonical_row_uses_no_whitespace() -> None:
    assert b" " not in canonical_row({"a": 1, "b": [1, 2], "c": {"d": 3}})


def test_canonical_row_keeps_non_ascii_as_utf8() -> None:
    canonical = canonical_row({"a": "ölçüm"})
    assert b"\\u" not in canonical
    assert canonical.decode("utf-8") == '{"a":"ölçüm"}'


def test_canonical_row_field_order_in_the_input_is_irrelevant() -> None:
    forward = canonical_row({"a": 1, "b": 2, "c": 3})
    backward = canonical_row({"c": 3, "b": 2, "a": 1})
    assert forward == backward


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_row_refuses_non_finite_floats(value: float) -> None:
    with pytest.raises(ValueError, match="Out of range"):
        canonical_row({"a": value})


def test_chain_hash_inserts_the_unit_separator() -> None:
    expected = hashlib.sha256(b"ab" + b"\x1f" + b"body").hexdigest()
    assert chain_hash("ab", b"body") == expected


def test_chain_hash_separator_prevents_boundary_collisions() -> None:
    # Without the separator these two would hash identical byte strings.
    assert chain_hash("aa", b"bb") != chain_hash("a", b"abb")


def test_compute_row_hash_is_chain_hash_of_the_canonical_bytes() -> None:
    fields = {"seq": 1, "extra": {"a": "ü"}}
    assert compute_row_hash("f" * 64, fields) == chain_hash(
        "f" * 64, canonical_row(fields)
    )


def test_genesis_hash_is_deterministic_and_salt_sensitive() -> None:
    org = "3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
    assert genesis_hash("salt", org) == genesis_hash("salt", org)
    assert genesis_hash("salt", org) != genesis_hash("pepper", org)
    assert genesis_hash("salt", org) != genesis_hash("salt", org.replace("3", "4"))


def test_genesis_hash_matches_the_documented_construction() -> None:
    expected = hashlib.sha256(
        b"salt" + b"\x1f" + b"audit-genesis" + b"\x1f" + b"org"
    ).hexdigest()
    assert genesis_hash("salt", "org") == expected


def test_merkle_root_requires_a_leaf() -> None:
    with pytest.raises(ValueError, match="at least one leaf"):
        merkle_root([])


def test_merkle_root_of_one_leaf_is_that_leaf() -> None:
    assert merkle_root(["ab"]) == "ab"


def test_merkle_root_of_two_leaves_concatenates_hex() -> None:
    assert merkle_root(["aa", "bb"]) == hashlib.sha256(b"aabb").hexdigest()


def test_merkle_root_is_order_sensitive() -> None:
    assert merkle_root(["aa", "bb"]) != merkle_root(["bb", "aa"])


def test_merkle_root_duplicates_the_last_leaf_on_odd_levels() -> None:
    left = hashlib.sha256(b"aabb").hexdigest()
    right = hashlib.sha256(b"cccc").hexdigest()
    expected = hashlib.sha256(f"{left}{right}".encode()).hexdigest()
    assert merkle_root(["aa", "bb", "cc"]) == expected


def test_merkle_root_does_not_mutate_its_input() -> None:
    leaves = ["aa", "bb", "cc"]
    merkle_root(leaves)
    assert leaves == ["aa", "bb", "cc"]


def test_canonical_row_output_reparses_to_the_same_object() -> None:
    fields = {"a": None, "b": True, "c": [1, {"d": "é"}], "e": 1.5}
    assert json.loads(canonical_row(fields)) == fields
