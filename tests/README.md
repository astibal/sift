# Sift tests

## Signature replay corpus

`signature_corpus.json` is the executable inventory of the production YAML
pack. Every runtime signature needs at least one positive replay case. Each
case feeds ordered chunks into a fresh duplex flow, so fragmentation,
direction and accumulated `flow.*` metadata behave like the real engine.

Use `reject` for targeted negative vectors. They are required where a short or
common prefix creates a meaningful false-positive risk; they are intentionally
optional for unambiguous long binary magics.

```json
{
  "name": "example fragmented protocol",
  "expect": "protocol.example",
  "reject": ["protocol.neighbour"],
  "chunks": [
    {"side": "L", "text": "first fragment"},
    {"side": "R", "hex": "01020304", "fields": {"flow.http2": true}}
  ]
}
```

## Coverage gate

The checked scope is the reusable `sift_core` library. Configure a dedicated
instrumented build and run its gate with:

```sh
cmake -S . -B build-coverage -DSIFT_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-coverage --target coverage
```

The target first runs the complete test suite and then requires at least 93%
line coverage. HTTP process/CLI integration remains visible in the regular
test suite but is deliberately reported separately from the reusable core.
