# SIFT test matrix

SIFT exposes detailed CTest results instead of reporting each test executable
as one opaque test. A full run currently reports 60 named tests grouped by
subsystem and protocol family.

```text
core.*                          runtime and supporting components
signatures.inventory            every production signature has a positive replay
signatures.<protocol-family>     corpus replays grouped by protocol family
integration.http-server         HTTP, DNS evidence, and LoreD integration
signatures.incubator-validation incubator schema and policy validation
policy.*                        signature naming and evidence-boundary rules
```

## Running tests

Build and run the complete matrix:

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

CTest labels provide focused runs and readable CI summaries:

```sh
ctest --test-dir build -L core
ctest --test-dir build -L protocol-family
ctest --test-dir build -L integration
ctest --test-dir build -R '^signatures\.(dns|doh)$'
```

The signature inventory test is separate from protocol-family replays. It
prevents a production signature from being added without a positive corpus
case, while family tests identify the affected protocol directly. A configured
family with no corpus cases fails instead of producing a misleading green test.

## Coverage

The coverage target runs the same CTest matrix and enforces at least 93% line
coverage over `sift_core`:

```sh
cmake -S . -B build-coverage -DSIFT_COVERAGE=ON
cmake --build build-coverage --target coverage
```

Coverage is a backstop rather than a substitute for the corpus. Protocol
signatures should include positive, fragmented, boundary, and false-positive
rejection cases whenever those variants are meaningful.
