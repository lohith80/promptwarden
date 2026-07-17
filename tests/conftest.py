from pathlib import Path

import pytest
import yaml

from promptwarden.config import Policy
from promptwarden.pipeline import Pipeline

CORPUS_DIR = Path(__file__).parent / "corpus"


def load_corpus(name: str):
    return yaml.safe_load((CORPUS_DIR / name).read_text(encoding="utf-8"))["samples"]


@pytest.fixture
def pipeline() -> Pipeline:
    return Pipeline(Policy())
