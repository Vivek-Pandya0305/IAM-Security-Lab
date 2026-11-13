"""pytest wrapper: `pytest -v`"""
import pytest
from lab import tests as T


@pytest.fixture(scope="module")
def ctx():
    return T.Ctx()


@pytest.mark.parametrize("t", T.REGISTRY, ids=lambda t: f"{t.group}::{t.name}")
def test_iam(t, ctx):
    actual, passed, evidence = t.fn(ctx)
    assert passed, f"expected: {t.expected} | actual: {actual} | {evidence}"
