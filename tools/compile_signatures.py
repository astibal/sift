#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import yaml

ALLOWED_OPERATIONS = {
    "prefix", "prefix_any", "hex_at", "tls_handshake",
    "line_prefix_within", "domain_suffix_any", "equals_any",
}
ALLOWED_SIDES = {"L", "R", "E", "H"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    document = yaml.safe_load(args.source.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("signatures"), list):
        raise SystemExit("signature pack must contain a signatures list")
    names = set()
    for index, rule in enumerate(document["signatures"]):
        if not isinstance(rule, dict) or not isinstance(rule.get("name"), str):
            raise SystemExit(f"signature {index} has no string name")
        if rule["name"] in names:
            raise SystemExit(f"duplicate signature: {rule['name']}")
        names.add(rule["name"])
        if not isinstance(rule.get("match"), list) or not rule["match"]:
            raise SystemExit(f"signature {rule['name']} has no match clauses")
        for clause in rule["match"]:
            if not isinstance(clause, dict) or clause.get("op") not in ALLOWED_OPERATIONS:
                raise SystemExit(f"signature {rule['name']} has an unsupported match operation")
            if "field" not in clause and clause.get("side", "E") not in ALLOWED_SIDES:
                raise SystemExit(f"signature {rule['name']} has an unsupported side")
            if "field" in clause and not isinstance(clause["field"], str):
                raise SystemExit(f"signature {rule['name']} has an invalid field name")
            if "value" not in clause and "values" not in clause and clause["op"] != "tls_handshake":
                raise SystemExit(f"signature {rule['name']} clause has no value")
        if rule.get("candidates") is not None and not isinstance(rule["candidates"], list):
            raise SystemExit(f"signature {rule['name']} candidates must be a list")
        for candidate in rule.get("candidates", []):
            if not isinstance(candidate, dict) or not isinstance(candidate.get("regex"), str):
                raise SystemExit(f"signature {rule['name']} has an invalid candidate")
            if candidate.get("side", "E") not in {"L", "R", "E"}:
                raise SystemExit(f"signature {rule['name']} candidate has an unsupported side")

    encoded = json.dumps(document, separators=(",", ":"), ensure_ascii=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "#pragma once\n#include <string_view>\n"
        "namespace sift::generated {\n"
        f'inline constexpr std::string_view signature_pack = R"SIFT({encoded})SIFT";\n'
        "}\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
