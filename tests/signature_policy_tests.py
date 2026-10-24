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


if __name__ == "__main__":
    main()
