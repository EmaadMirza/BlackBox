"""Canonicalization properties over nested JSON, excluding forbidden floats."""

from hypothesis import given
from hypothesis import strategies as st

from libs.blackbox_core.canonical import canonicalize

text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=20)
values = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**53 - 1), 2**53 - 1) | text,
    lambda children: (
        st.lists(children, max_size=5)
        | st.dictionaries(st.text(alphabet="abcdef", max_size=8), children, max_size=5)
    ),
    max_leaves=20,
)


@given(values)
def test_idempotent(value: object) -> None:
    encoded = canonicalize(value)
    assert canonicalize(encoded) == encoded


@given(st.dictionaries(st.text(alphabet="abcdef", max_size=8), values, max_size=10))
def test_key_order(value: dict[str, object]) -> None:
    assert canonicalize(value) == canonicalize(dict(reversed(list(value.items()))))
