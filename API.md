# Sift inspection API

Sift accepts an SXBN001 envelope containing JSON metadata followed by the raw
payload bytes. The payload is authoritative content; metadata describes the
requestor's observation of the surrounding flow.

When LoreD enrichment is configured, the normal verdict contains a `lore`
member with the `lored-verdict/1` response. Sift builds the deliberately small
query from `flow.tls.sni`, HTTP host/authority, protocol observations, and these
optional destination fields:

```text
flow.destination.address
flow.destination.port
flow.transport
```

Compatibility aliases `flow.dst.ip`, `flow.dst.port`, `flow.remote.ip`, and
`flow.remote.port` are accepted. Lore candidates and Sift payload signatures
remain separate evidence domains.

## Passive DNS evidence

`POST /api/dns-observation` records a client-scoped DNS answer for later flow
correlation. Producer identity follows the same tenant and instance rules as
payload inspection:

```json
{
  "format": "sift-dns-observation/1",
  "identity": {"tenant": "default", "instance": "helmut-edge-01"},
  "client_address": "10.0.0.42",
  "hostname": "www.example.com",
  "addresses": ["203.0.113.10", "2001:db8::10"],
  "cname_chain": ["edge.example.net"],
  "ttl_seconds": 300
}
```

The cache key contains tenant, producer instance, client address and returned
destination address. An observation is never shared across tenants,
requestors, or clients. TTL starts when Sift accepts it and is capped at 24
hours. A later `connection-content` carrying `flow.source.address` and
`flow.destination.address` receives a `dns_evidence` result. On a match Sift
also adds internal metadata:

```text
flow.dns.forward.match = true
flow.dns.forward.hostname = <observed query name>
```

The hostname becomes a LoreD host hint only when HTTP Host/authority is absent.
It remains supporting evidence rather than a payload signature verdict.

Relevant observations accumulate for the flow lifetime. An unchanged query is
served from the flow state, and a successful match suppresses later queries for
that flow. Unknown results may be refined by later SNI, authority or protocol
evidence, but no flow sends more than five LoreD requests. A bounded shared
five-minute cache also reuses identical results across flows. `connection-stop`
removes the per-flow Lore state; the shared cache remains available until TTL
expiry or capacity eviction.

## Request

```json
{
  "action": "connection-content",
  "id": "stable-flow-id",
  "identity": {
    "tenant": "default",
    "instance": "helmut-edge-01"
  },
  "details": {
    "info": {
      "session": "human-readable-flow-label",
      "side": "L",
      "payload_layer": "tcp",
      "L7_payload_start": [120, 256],
      "L7_payload_end": [180, 310],
      "L7_encoding": ["gzip", ""],
      "flow.tls.sni": "rr1---sn.example.googlevideo.com",
      "flow.http2": true,
      "flow.http2.method": "GET",
      "flow.http2.scheme": "https",
      "flow.http2.authority": "rr1---sn.example.googlevideo.com",
      "flow.http2.path": "/videoplayback?id=example",
      "flow.http2.url": "https://rr1---sn.example.googlevideo.com/videoplayback?id=example"
    }
  }
}
```

The JSON is followed by the payload declared by the SXBN001 envelope. Missing
optional fields do not invalidate a request.

## Payload position and layer

`side` and `payload_layer` say where the attached bytes were observed.
`L7_payload_start`, `L7_payload_end`, and `L7_encoding` are parallel arrays.
Element `i` describes one L7 user-payload range in the attached content buffer;
the start is inclusive and the end is exclusive. Multiple ranges allow framed
transports such as HTTP/1 chunked encoding to exclude their framing bytes.

The special values defined by Smithproxy retain their meaning:

```text
[-1, -1]  L7 user-payload location is unknown
[ 0,  0]  this content buffer positively contains no L7 user payload
```

Known non-empty ranges are bounds-checked, extracted, and concatenated in array
order. Ranges with different `L7_encoding` values use separate inference state,
so compressed and plain bytes are never joined. Structural inference currently
uses only ranges with an empty encoding. Values such as `gzip` are retained but
must be decoded by a future bounded decoder before their content is inspected.

The optional `payload_stream` may distinguish multiplexed application streams.
It may be a string or an integer. When absent, Sift also accepts
`flow.http2.stream_id` or `flow.http3.stream_id`. Without one of these fields,
the range arrays alone cannot distinguish interleaved HTTP/2 or HTTP/3 streams.

Sift keeps structural inference state under:

```text
(tenant, instance, session, side, payload_layer, payload_stream, L7_encoding)
```

When valid L7 ranges are present, structure inference sees only their extracted
bytes and reports `http1.payload`, `http2.payload`, `http3.payload`, or the
generic `l7.payload` as its layer. With unknown L7 location, inference falls
back to the complete `payload_layer` stream. A known-empty range contributes no
bytes.

The experimental structure engine internally uses compact candidate names such
as:

```json
{
  "candidate": "protocol.struct.tlv.16m.2x.2x.2l.le.lv"
}
```

Here `16m` is the uninterpreted prefix length, each `2x` is an unknown two-byte
field, `2l` is the two-byte length field, `le` is its byte order, and `lv` says
the length counts only the value. Sift can return several candidates when the
same record boundaries admit more than one equally plausible field layout.
These observations are deliberately not returned as verdict matches and do not
appear in `signatures.by_name`. `/api/stats` exposes only aggregate structure
`scans`, `candidates`, and `published: 0` while the inference remains
experimental.

Structural inference succeeds only when every inferred jump is valid and the
last record ends exactly at the end of all bytes currently accumulated for the
probe. An incomplete final record is pending evidence, not a partial match;
Sift retries it when more bytes arrive.

Length fields are restricted to two or four bytes. One-byte lengths are too
likely to produce accidental jump chains and are deliberately not inferred;
one-byte unknown fields (`1x`) remain supported.

## Multitenant flow identity

Flow state is isolated by the tuple:

```text
(identity.tenant, identity.instance, id || details.info.session)
```

`identity.tenant` defaults to `default`. `identity.instance` is the stable
producer identity and should be configured explicitly by every requestor.
For compatibility, a non-empty top-level string `source` is accepted as the
instance identity. If neither value is present, Sift uses the numeric peer IP
address. The IP fallback is intentionally visible through
`identity.ip_fallback_requests` in `/api/stats`.

Declared and peer-IP identities occupy distinct internal namespaces. An
explicit instance string that happens to look like the peer IP therefore
cannot merge with a legacy IP-fallback flow.

The peer IP is only a collision-prevention fallback, not an authentication
mechanism. Deployments with mutually untrusted tenants must bind the declared
identity to transport authentication or an API credential.

`id` is the authoritative machine flow identifier shared by content and
`connection-stop` events. The human-readable `details.info.session` value is
used as a compatibility fallback only when `id` is absent.

Requests without both `id` and `details.info.session` are inspected as
one-request anonymous flows and immediately discarded. They can classify one
payload but cannot accumulate stream state or collide with another anonymous
request.

`connection-start` is optional and idempotent. It pre-creates or touches the
flow but never clears evidence already received. `connection-stop` removes the
flow and installs a short tombstone, so a late asynchronous start or content
event cannot resurrect the connection. Content still creates a missing flow
for compatibility with requestors that do not emit lifecycle events.

Smithproxy sends the explicit identity fields. Its corresponding settings are:

```text
settings.webhook.sift_tenant_id
settings.webhook.sift_instance_id
```

An empty Smithproxy instance setting falls back to its configured webhook
`hostid`, and then to the local hostname. This fallback happens at the
requestor, so Sift still receives an explicit instance identity. Smithproxy
snapshots its Sift identity for the lifetime of the process; changing either
identity setting requires a restart and cannot split an active flow.

## Runtime flow limits

Sift retains only a bounded prefix of each direction as verifier evidence.
Hyperscan continues consuming every byte through its streaming state; traffic
counters therefore describe the complete input even after the evidence prefix
is full. The prefix cannot be reduced below the largest requirement derived
from the compiled signature pack.

Idle flow TTL decreases logarithmically as the flow table fills: it is 24 hours
for an empty table and reaches 10 minutes at capacity by default. A periodic
lazy sweep removes expired flows, and the oldest flow is evicted if the hard
capacity is reached first. Metadata names, values, structural probes, and stop
tombstones are bounded independently.

`GET /api/config` returns the effective limits and current computed TTL.
`POST /api/config` applies a partial JSON update without restarting Sift and is
accepted only from a loopback client. Unknown keys, unsafe evidence limits,
out-of-range values, and inverted TTL bounds are rejected atomically. Defaults:

```json
{
  "evidence_bytes_per_side": 65536,
  "max_flows": 10000,
  "min_idle_ttl_seconds": 600,
  "max_idle_ttl_seconds": 86400,
  "tombstone_ttl_seconds": 30,
  "sweep_interval_seconds": 5,
  "max_field_names_per_flow": 128,
  "max_values_per_field": 64,
  "max_structure_probes_per_flow": 8
}
```

`GET /api/stats` exposes active, expired and evicted flow counts, table
utilization, current dynamic TTL, tombstones, dropped late payloads, retained
evidence memory, and dropped metadata counts.

## Evidence and trust

| Namespace | Meaning | Classification use |
|---|---|---|
| raw SXBN payload | Bytes inspected directly by Sift | Authoritative content evidence |
| `flow.*` | A fact observed and asserted by the requestor for this flow | Rules may explicitly consume it |
| `context.*` | Routing or deployment context | Supplemental only |
| `hint.*` | Unverified suggestion | Never sufficient by itself |
| `payload.*` | Evidence extracted internally by Sift from raw bytes | Reserved; requestor values are ignored |

Sift does not cryptographically prove a `flow.*` assertion. Trust in those
fields comes from the authenticated or isolated transport used to reach the
API. Deployments that allow untrusted clients to submit inspection requests
must not treat requestor-provided flow observations as trusted classification
evidence.

Only `flow.*` string/boolean values and arrays of those values are currently
retained by the runtime. Unknown fields are ignored. A field remains associated
with its session until `connection-stop` closes that flow.

The `payload_*` transport fields above describe the attached raw bytes. They
are not classification assertions and are deliberately outside the reserved
`payload.*` evidence namespace.

## Canonical flow observations

Flat dotted names are the wire format. Initial canonical fields are:

```text
flow.tls.sni
flow.tls.alpn
flow.http1
flow.http1.method | host      | path | scheme | url
flow.http2
flow.http2.method | authority | path | scheme | url
flow.http3
flow.http3.method | authority | path | scheme | url
```

`flow.tls.sni` and `flow.tls.alpn` mean the requestor observed the values during
TLS processing. ALPN is the negotiated application protocol, not a port-based
guess. The registered `imap` and `pop3` identifiers may therefore support
`enc.tls.protocol.imap` and `enc.tls.protocol.pop3`; SMTP has no registered
ALPN identifier and must not be inferred this way.
`flow.http1`, `flow.http2`, and `flow.http3` set to `true` mean the requestor's
application inspection engine positively identified that protocol; they must
not be inferred merely from a port number or ALPN. `host` and `authority` mean
the requestor obtained the value from the corresponding parsed application
protocol. They are not aliases: preserving the layer lets rules state exactly
which evidence they accept.

`path` contains the path and optional query component. `url` is the requestor's
normalized composition of the parsed scheme, authority/host, path, and query;
it is convenient derived flow evidence, while the individual fields preserve
the actual parsed components. Fields are omitted until the requestor has a
complete parsed request.

Smithproxy emits the TLS observation and the HTTP/1.x and HTTP/2 observations
available from its application inspector. Its HTTP/3 path submits decoded
initial QPACK request fields as a metadata-only `connection-content` event with
`payload_layer: http3.headers`. Response headers and request trailers do not
assert request metadata.

## Rule binding

Rules opt in to requestor observations explicitly:

```yaml
- name: app.youtube.video
  match:
    - field: flow.tls.sni
      op: domain_suffix_any
      values: [googlevideo.com]
```

A flow observation has no classification effect unless a compiled YAML rule
references its exact field name.

For example, requestor-confirmed HTTP/2 is deliberately a YAML rule rather
than a C++ special case:

```yaml
- name: protocol.http2
  match:
    - field: flow.http2
      op: equals_any
      values: ["true"]
```

The same generated pack contains equivalent `protocol.http1` and
`protocol.http3` rules. No protocol assertion is implemented as a C++ special
case.
