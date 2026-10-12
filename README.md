# Sift

Sift is a stateful streaming payload identification engine. Give it bytes and
it returns the protocol and content shapes it can establish from those bytes.
Network addresses and ports are optional hints, never primary evidence.

`siftd` exposes the engine over a deliberately small HTTP/SXBN001 API. It
accepts bidirectional stream chunks, keeps per-flow state and returns a verdict.
Sift requires Intel Hyperscan (`libhyperscan-dev` on Debian/Ubuntu); there is no
silent `std::regex` fallback.

The bootstrap engine compiles its cheap pattern gates into one Hyperscan
database per direction. Each flow owns left and right streaming scanner state;
Hyperscan emits candidate rule IDs and the stateful matchers perform the final
multi-direction and structural checks.

```text
any producer -- JSON metadata + raw bytes --> siftd
Smithproxy   -- SXBN001 -------------------> siftd
Spider       -- replay/SXBN001 ------------> siftd
```

## Build

Debian/Ubuntu dependencies:

```sh
sudo apt install cmake g++ pkg-config libhyperscan-dev \
  libmicrohttpd-dev nlohmann-json3-dev
git submodule update --init
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Run the daemon with `build/siftd`. The default endpoint is
`http://127.0.0.1:18081/webhook`.

## API

An SXBN001 request is a 25-byte ASCII header, JSON metadata and an unencoded
binary payload:

```text
SXBN001:<8 hex JSON bytes>:<8 hex payload bytes><JSON><payload>
```

Smithproxy's existing `connection-content` schema is supported. The public API
will also accept progressively more relaxed metadata; payload bytes remain the
only essential input.

Runtime counters are available as JSON from `GET /api/stats`. The existing
timing section reports both runtime `engine_delay_us` (flow management and
signature search) and content request `total_delay_us` (request decoded through
verdict produced). Network and broker latency is deliberately not included.
Timing medians use a bounded rolling
window of the latest 4096 samples; lifetime minimum, maximum and average remain
available alongside it.
`/api/status` endpoint returns the same snapshot, while `/api/health` remains
available for deployment health checks. The snapshot includes flow lifecycle,
directional traffic, payload sizes, per-signature matches, decisions, uptime,
and inspection latency. End-to-end round-trip latency requires telemetry from
Smithproxy and its communication broker and is therefore reported as pending.

All protocol and application signatures live exclusively in
`signatures/default.yaml`. The build validates and compiles that pack into an
embedded artifact consumed by the generic runtime matcher; C++ contains no
individual signature definitions. Adding or changing a signature therefore
never requires editing the engine. Python 3 with PyYAML is required when
building the compiled pack. See [SIGNATURE_POLICY.md](SIGNATURE_POLICY.md) for
the mandatory rules governing signature changes and [API.md](API.md) for the
wire schema, evidence namespaces, and trust boundary.
