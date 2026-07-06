from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_benchmark_dataset import ENTITY_TYPES, RELATIONSHIP_TYPES, generate_dataset  # noqa: E402


def test_benchmark_dataset_generator_is_deterministic_and_covers_types(tmp_path) -> None:
    first_output = tmp_path / "first.jsonl"
    first_manifest_path = tmp_path / "first-manifest.json"
    second_output = tmp_path / "second.jsonl"
    second_manifest_path = tmp_path / "second-manifest.json"

    first = generate_dataset(
        output_path=first_output,
        manifest_path=first_manifest_path,
        seed=123,
        tenants=2,
        entity_target=200,
        relationship_target=128,
    )
    second = generate_dataset(
        output_path=second_output,
        manifest_path=second_manifest_path,
        seed=123,
        tenants=2,
        entity_target=200,
        relationship_target=128,
    )

    assert first["unique_entities"] >= 200
    assert first["unique_relationships"] == 128
    assert set(first["entity_counts"]) == set(ENTITY_TYPES)
    assert all(first["relationship_counts"][relationship_type] > 0 for relationship_type in RELATIONSHIP_TYPES)
    assert first_output.read_text(encoding="utf-8") == second_output.read_text(encoding="utf-8")
    assert first == json.loads(first_manifest_path.read_text(encoding="utf-8"))
    assert second["relationship_counts"] == first["relationship_counts"]


def test_benchmark_dataset_generator_fails_when_relationship_capacity_is_too_small(tmp_path) -> None:
    with pytest.raises(ValueError, match="exceeds generated pool capacity"):
        generate_dataset(
            output_path=tmp_path / "too-large.jsonl",
            manifest_path=tmp_path / "too-large-manifest.json",
            seed=123,
            tenants=1,
            entity_target=10,
            relationship_target=10_000,
        )
