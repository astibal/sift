#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import yaml

ALLOWED_OPERATIONS = {
    "prefix", "prefix_any", "prefix_any_ci", "decimal_prefix", "hex_at", "tls_handshake",
    "line_prefix_within", "domain_suffix_any", "equals_any", "uint_at",
    "size_from_uint_at", "label_sequence_at", "size_between", "ber_sequence",
    "ber_frame", "candidate_seen",
}
ALLOWED_SIDES = {"L", "R", "E", "H"}
ENCRYPTED_NAMESPACES = {
    "enc.tls.": "flow.tls.",
    "enc.quic.": "flow.quic.",
}


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
        encrypted_field_prefix = next(
            (field_prefix for name_prefix, field_prefix in ENCRYPTED_NAMESPACES.items()
             if rule["name"].startswith(name_prefix)),
            None,
        )
        if rule["name"].startswith("enc.") and encrypted_field_prefix is None:
            raise SystemExit(
                f"signature {rule['name']} uses an unsupported encrypted namespace")
        encrypted_evidence = False
        for clause in rule["match"]:
            if not isinstance(clause, dict) or clause.get("op") not in ALLOWED_OPERATIONS:
                raise SystemExit(f"signature {rule['name']} has an unsupported match operation")
            has_field = "field" in clause
            has_fields = "fields" in clause
            if has_field and has_fields:
                raise SystemExit(
                    f"signature {rule['name']} clause cannot use field and fields together")
            if not has_field and not has_fields and clause.get("side", "E") not in ALLOWED_SIDES:
                raise SystemExit(f"signature {rule['name']} has an unsupported side")
            if has_field and not isinstance(clause["field"], str):
                raise SystemExit(f"signature {rule['name']} has an invalid field name")
            if has_fields and (
                    not isinstance(clause["fields"], list) or
                    not clause["fields"] or
                    not all(isinstance(field, str) and field for field in clause["fields"])):
                raise SystemExit(f"signature {rule['name']} has invalid field names")
            clause_fields = ([clause["field"]] if has_field else
                             clause.get("fields", []))
            if encrypted_field_prefix is not None:
                if any(field.startswith("flow.http") for field in clause_fields):
                    raise SystemExit(
                        f"encrypted signature {rule['name']} uses plaintext HTTP evidence")
                encrypted_evidence |= any(
                    field.startswith(encrypted_field_prefix) for field in clause_fields)
            if ("value" not in clause and "values" not in clause and
                    clause["op"] not in {
                        "tls_handshake", "decimal_prefix", "uint_at",
                        "size_from_uint_at", "label_sequence_at", "size_between",
                        "ber_sequence", "ber_frame",
                        "candidate_seen",
                    }):
                raise SystemExit(f"signature {rule['name']} clause has no value")
            if clause["op"] == "decimal_prefix":
                if not isinstance(clause.get("digits"), int) or clause["digits"] < 1:
                    raise SystemExit(
                        f"signature {rule['name']} decimal_prefix has invalid digits")
                if not isinstance(clause.get("separators"), str) or not clause["separators"]:
                    raise SystemExit(
                        f"signature {rule['name']} decimal_prefix has invalid separators")
            if clause["op"] == "hex_at" and not isinstance(clause.get("value"), str):
                raise SystemExit(f"signature {rule['name']} hex_at value must be a quoted string")
            if clause["op"] in {"uint_at", "size_from_uint_at"}:
                if clause.get("width") not in {1, 2, 3, 4}:
                    raise SystemExit(f"signature {rule['name']} has an invalid integer width")
                if clause.get("endian", "be") not in {"be", "le"}:
                    raise SystemExit(f"signature {rule['name']} has an invalid byte order")
            if clause["op"] == "label_sequence_at" and not isinstance(
                    clause.get("offset"), int):
                raise SystemExit(f"signature {rule['name']} label sequence has no offset")
            if clause["op"] == "ber_sequence":
                if not isinstance(clause.get("children"), list) or not clause["children"]:
                    raise SystemExit(f"signature {rule['name']} BER sequence has no children")
                for child in clause["children"]:
                    if not isinstance(child, dict) or not any(
                            key in child for key in ("tag", "tag_min", "tag_max")):
                        raise SystemExit(
                            f"signature {rule['name']} has an invalid BER child")
            if clause["op"] == "ber_frame" and not any(
                    key in clause for key in ("tag", "tags", "tag_min", "tag_max")):
                raise SystemExit(f"signature {rule['name']} BER frame has no tag constraint")
            if clause["op"] == "candidate_seen" and not rule.get("candidates"):
                raise SystemExit(
                    f"signature {rule['name']} candidate_seen requires candidates")
        if rule.get("candidates") is not None and not isinstance(rule["candidates"], list):
            raise SystemExit(f"signature {rule['name']} candidates must be a list")
        for candidate in rule.get("candidates", []):
            if not isinstance(candidate, dict) or not isinstance(candidate.get("regex"), str):
                raise SystemExit(f"signature {rule['name']} has an invalid candidate")
            if candidate.get("side", "E") not in {"L", "R", "E"}:
                raise SystemExit(f"signature {rule['name']} candidate has an unsupported side")
        if encrypted_field_prefix is not None and not encrypted_evidence:
            raise SystemExit(
                f"encrypted signature {rule['name']} has no {encrypted_field_prefix} evidence")

    # An encrypted-evidence verdict must never be the only vocabulary exposed
    # for an application or protocol. The matching evidence can differ, but
    # consumers must be able to use the same plain label after inspection.
    for name in names:
        for prefix in ENCRYPTED_NAMESPACES:
            if not name.startswith(prefix):
                continue

            counterpart = name[len(prefix):]
            has_counterpart = counterpart in names or any(
                plain.startswith(counterpart + ".") for plain in names)
            if not has_counterpart:
                raise SystemExit(
                    f"encrypted signature {name} has no plain counterpart "
                    f"{counterpart}")

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
