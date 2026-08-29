"""Shared fixtures.

``scripts`` is put on the path so the tests and the published-example generator
build chains through exactly the same code. A drift between what is tested and
what is published is the one failure this repository cannot afford.
"""

import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import chain

ROOT = Path(__file__).resolve().parent.parent
VECTOR_DIR = ROOT / "tests" / "vectors"
_TEMPLATE = chain.build_bundle([6, 5, 7, 4])


@pytest.fixture
def bundle() -> dict[str, Any]:
    """A valid four-day bundle, fresh for every test."""
    return deepcopy(_TEMPLATE)


@pytest.fixture
def builder() -> ModuleType:
    """The chain builder, for tests that need a different chain shape."""
    return chain
