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

## Optional LoreD enrichment

Siftd can enrich its payload verdict through the small `lored-verdict/1` API.
LoreD remains disabled unless its query URL is configured:

```sh
build/siftd --lored-url http://127.0.0.1:8091/v1/query
```

Smithproxy or another caller must explicitly request enrichment through
`requirements.lored.mode`. An optional failed lookup appears as
`lored.status: unavailable`, while the Sift verdict remains usable. A required
applicable failed lookup returns HTTP 503. Requests
without an IP, SNI or HTTP host are `not-applicable`, because LoreD has nothing
meaningful to query. The timeout defaults to 50 ms and is configurable through
`--lored-timeout-ms`.

LoreD candidates remain nested under `lored`; Sift never presents them as
payload signature matches. `/api/diagnostics` exposes LoreD requests, outcomes
and latency.

Complete HTTP URLs are private by default. They are forwarded only when the
request sets `requirements.lored.include_url` to true; destination IP, port,
transport, SNI, Host/authority and protocol remain the default query surface.

Sift accumulates relevant flow observations and sends a new query only when
the normalized destination, SNI, HTTP host/authority or protocol fingerprint
changes. Each flow can issue at most five actual LoreD requests. A matched
service stops further queries for that flow. Identical queries across flows use
a bounded 4096-entry cache with a five-minute TTL. Both limits are intentionally
conservative defaults for a shared Internet-facing LoreD service.

```text
any producer -- JSON metadata + raw bytes --> siftd
Smithproxy   -- SXBN001 -------------------> siftd
Spider       -- replay/SXBN001 ------------> siftd
```

## Build

Debian/Ubuntu dependencies:

```sh
sudo apt install cmake g++ pkg-config libhyperscan-dev \
  libmicrohttpd-dev libcurl4-openssl-dev nlohmann-json3-dev
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

Flow state is multitenant: tenant, producer instance and session identifiers
form one composite key. Legacy `source` values remain supported, with the
numeric peer IP used only when the request carries no producer identity. See
[API.md](API.md) for identity precedence and trust boundaries.

Passive client-scoped DNS answers can be submitted to
`POST /api/dns-observation`. Sift correlates them with later source/destination
flow metadata until the supplied TTL expires; see
[API.md](API.md#passive-dns-evidence).

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
`GET /api/diagnostics` wraps this engine snapshot with Sift HTTP transport
counters, byte totals, response classes, decode errors, and the timestamps and
status of the latest completed request.
Bounded flow evidence, a utilization-sensitive idle TTL, hard flow capacity,
and late-event tombstones prevent missing or reordered lifecycle callbacks from
growing runtime state without limit. Effective limits are visible through
`GET /api/config`; loopback clients may update them online with a partial
`POST /api/config` request. See [API.md](API.md#runtime-flow-limits).

All protocol and application signatures live exclusively in
`signatures/default.yaml`. The build validates and compiles that pack into an
embedded artifact consumed by the generic runtime matcher; C++ contains no
individual signature definitions. Adding or changing a signature therefore
never requires editing the engine. Python 3 with PyYAML is required when
building the compiled pack. See [SIGNATURE_POLICY.md](SIGNATURE_POLICY.md) for
the mandatory rules governing signature changes and [API.md](API.md) for the
wire schema, evidence namespaces, and trust boundary.

Plausible but unverified rules live in the inert
[`signatures/incubator/`](signatures/incubator/) inventory. They retain pinned
research provenance but are not compiled or consulted by `siftd`. Candidates
move into the runtime pack only after the documented plaintext,
encrypted/metadata-visible, negative and streaming-delivery checks pass.
