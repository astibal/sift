#!/usr/bin/env python3
"""Validate inert signature candidates without promoting them to runtime."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml


ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]+")
ALLOWED = {
    "transport": {"tcp", "udp", "any"},
    "layer": {"protocol", "security", "service", "content", "tunnel"},
    "confidence": {"hint", "probable", "high", "certain"},
    "logic": {"all", "any"},
}


def load_pack(path: Path) -> list[dict]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError(f"{path}: expected a version 1 mapping")
    signatures = document.get("signatures")
    if not isinstance(signatures, list):
        raise ValueError(f"{path}: signatures must be a list")
    return signatures


def validate(paths: list[Path]) -> tuple[int, list[str]]:
    errors: list[str] = []
    seen: dict[str, Path] = {}
    count = 0
    for path in paths:
        try:
            signatures = load_pack(path)
        except Exception as error:
            errors.append(str(error))
            continue
        count += len(signatures)
        for index, signature in enumerate(signatures):
            where = f"{path}:signatures[{index}]"
            if not isinstance(signature, dict):
                errors.append(f"{where}: candidate must be a mapping")
                continue
            candidate_id = signature.get("id")
            if not isinstance(candidate_id, str) or not ID_PATTERN.fullmatch(candidate_id):
                errors.append(f"{where}: invalid or missing id")
            elif candidate_id in seen:
                errors.append(f"{where}: duplicate id also present in {seen[candidate_id]}")
            else:
                seen[candidate_id] = path
                where = f"{path}:{candidate_id}"
            for key, values in ALLOWED.items():
                if signature.get(key) not in values:
                    errors.append(f"{where}: invalid {key}")
            if not isinstance(signature.get("result"), dict) or not signature["result"]:
                errors.append(f"{where}: result must be a non-empty mapping")
            if not isinstance(signature.get("clauses"), list) or not signature["clauses"]:
                errors.append(f"{where}: clauses must be a non-empty list")
            sources = signature.get("sources")
            if not isinstance(sources, list) or not sources:
                errors.append(f"{where}: at least one source is required")
            elif any(not isinstance(source, dict) or not source.get("project") or
                     not source.get("url") for source in sources):
                errors.append(f"{where}: every source requires project and url")
    return count, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    arguments = parser.parse_args()
    count, errors = validate(arguments.paths)
    production_path = Path(__file__).resolve().parents[1] / "signatures" / "default.yaml"
    production = yaml.safe_load(production_path.read_text(encoding="utf-8"))
    production_ids = {rule["name"] for rule in production["signatures"]}
    incubator_ids = {
        signature["id"]
        for path in arguments.paths
        for signature in load_pack(path)
        if isinstance(signature, dict) and isinstance(signature.get("id"), str)
    }
    overlap = sorted(production_ids & incubator_ids)
    if overlap:
        errors.append("already promoted candidates remain in incubator: " + ", ".join(overlap))
    if errors:
        print("\n".join(errors))
        return 1
    print(f"ok: {len(arguments.paths)} incubator packs, {count} candidates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
