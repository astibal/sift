# Sift inspection API

Sift accepts an SXBN001 envelope containing JSON metadata followed by the raw
payload bytes. The payload is authoritative content; metadata describes the
requestor's observation of the surrounding flow.

## Request

```json
{
  "action": "connection-content",
  "id": "request-id",
  "details": {
    "info": {
      "session": "stable-flow-id",
      "side": "L",
      "payload_layer": "tcp",
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

## Canonical flow observations

Flat dotted names are the wire format. Initial canonical fields are:

```text
flow.tls.sni
flow.http1
flow.http1.method | host      | path | scheme | url
flow.http2
flow.http2.method | authority | path | scheme | url
flow.http3
flow.http3.method | authority | path | scheme | url
```

`flow.tls.sni` means the requestor observed the value during TLS processing.
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
