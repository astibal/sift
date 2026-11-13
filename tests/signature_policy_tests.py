#!/usr/bin/env python3
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


def compile_pack(compiler: Path, signatures: list[dict]) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "pack.yaml"
        output = root / "pack.hpp"
        source.write_text(
            yaml.safe_dump({"version": 1, "signatures": signatures}),
            encoding="utf-8",
        )
        return subprocess.run(
            [sys.executable, str(compiler), str(source), str(output)],
            capture_output=True,
            text=True,
            check=False,
        )


def compile_manifest(
    compiler: Path, manifest: dict, included: dict[str, dict]
) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "pack.yaml"
        output = root / "pack.hpp"
        source.write_text(yaml.safe_dump(manifest), encoding="utf-8")
        for name, document in included.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(yaml.safe_dump(document), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(compiler), str(source), str(output)],
            capture_output=True,
            text=True,
            check=False,
        )


def rule(name: str, field: str) -> dict:
    return {
        "name": name,
        "match": [{"field": field, "op": "equals_any", "values": ["test"]}],
    }


def main() -> None:
    compiler = Path(sys.argv[1])
    plain = rule("protocol.demo", "flow.http2.subprotocol")

    valid = compile_pack(
        compiler,
        [plain, rule("enc.tls.protocol.demo", "flow.tls.alpn")],
    )
    assert valid.returncode == 0, valid.stderr

    unsupported = compile_pack(
        compiler,
        [plain, rule("enc.http.protocol.demo", "flow.http2.subprotocol")],
    )
    assert unsupported.returncode != 0
    assert "unsupported encrypted namespace" in unsupported.stderr

    plaintext = compile_pack(
        compiler,
        [plain, rule("enc.tls.protocol.demo", "flow.http2.subprotocol")],
    )
    assert plaintext.returncode != 0
    assert "plaintext HTTP evidence" in plaintext.stderr

    missing = compile_pack(
        compiler,
        [plain, rule("enc.tls.protocol.demo", "flow.dst.address")],
    )
    assert missing.returncode != 0
    assert "has no flow.tls. evidence" in missing.stderr

    included = compile_manifest(
        compiler,
        {"version": 1, "includes": ["protocols/demo.yaml"]},
        {"protocols/demo.yaml": {"signatures": [plain]}},
    )
    assert included.returncode == 0, included.stderr

    duplicate_include = compile_manifest(
        compiler,
        {"version": 1, "includes": ["demo.yaml", "demo.yaml"]},
        {"demo.yaml": {"signatures": [plain]}},
    )
    assert duplicate_include.returncode != 0
    assert "duplicate signature include" in duplicate_include.stderr

    escaped_include = compile_manifest(
        compiler,
        {"version": 1, "includes": ["../outside.yaml"]},
        {},
    )
    assert escaped_include.returncode != 0
    assert "escapes pack root" in escaped_include.stderr


if __name__ == "__main__":
    main()
