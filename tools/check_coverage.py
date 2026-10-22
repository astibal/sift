#!/usr/bin/env python3
"""Enforce line coverage for first-party Sift core sources using GCC gcov."""

import argparse
import gzip
import json
import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--minimum", type=float, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--object", type=Path, action="append", required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    covered = 0
    executable = 0
    per_file = {}

    with tempfile.TemporaryDirectory(prefix="sift-coverage-") as directory:
        output = Path(directory)
        for index, object_file in enumerate(args.object):
            invocation = output / str(index)
            invocation.mkdir()
            subprocess.run(
                ["gcov", "--json-format", str(object_file.resolve())],
                cwd=invocation,
                check=True,
                stdout=subprocess.DEVNULL,
            )

            for report in invocation.glob("*.gcov.json.gz"):
                with gzip.open(report, "rt", encoding="utf-8") as stream:
                    document = json.load(stream)
                for source in document["files"]:
                    filename = Path(source["file"]).resolve()
                    if root not in filename.parents or filename.suffix != ".cpp":
                        continue
                    # A line marked unexecuted_block is still executable; it is
                    # precisely one of the lines a coverage gate must count.
                    lines = [line for line in source["lines"] if "count" in line]
                    file_executable = len(lines)
                    file_covered = sum(1 for line in lines if line["count"] > 0)
                    previous_covered, previous_executable = per_file.get(filename, (0, 0))
                    per_file[filename] = (
                        max(previous_covered, file_covered),
                        max(previous_executable, file_executable),
                    )

    for filename, (file_covered, file_executable) in sorted(per_file.items()):
        covered += file_covered
        executable += file_executable
        percentage = 100.0 * file_covered / file_executable
        print(f"{filename.relative_to(root)}: {file_covered}/{file_executable} "
              f"({percentage:.2f}%)")

    percentage = 100.0 * covered / executable if executable else 0.0
    print(f"Sift core line coverage: {covered}/{executable} ({percentage:.2f}%)")
    if percentage < args.minimum:
        raise SystemExit(
            f"coverage {percentage:.2f}% is below required {args.minimum:.2f}%")


if __name__ == "__main__":
    main()
