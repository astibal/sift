# Signature policy

## Non-negotiable rule

All protocol, application, security, and content signatures live exclusively
in YAML signature packs.

```text
YAML pack -> validation/compiler -> generated artifact -> generic runtime
```

Never add an individual signature, hostname, application identity, protocol
constant, byte pattern, or candidate regular expression directly to C++ code.
This includes bootstrap rules, temporary experiments, demonstrations, and
"just one" emergency detector.

## C++ responsibilities

C++ may implement only reusable matching primitives and runtime machinery,
for example:

- directional flow state;
- generic prefix, byte-offset, hostname, and structured-field operators;
- Hyperscan candidate execution;
- compiled-pack loading and validation;
- match accounting and verdict generation.

Adding a new generic operator is acceptable only when it is useful beyond one
specific signature. The operator must not contain product names, domains,
protocol-specific constants, or hidden signature data.

Generic structural inference may publish runtime-derived evidence under
`protocol.struct.*`. Such identifiers describe only an observed layout (for
example field widths, byte order, and length semantics), never the identity of
a concrete protocol. Mapping that layout to a protocol or application remains
a YAML signature decision.

## Signature changes

A signature change must:

1. modify a YAML pack;
2. pass pack compilation and schema validation;
3. include positive and relevant negative test vectors;
4. preserve source attribution when the rule originates elsewhere;
5. expose a stable, namespaced identifier such as `protocol.http2` or
   `app.youtube.video`.

Generated artifacts are build products. YAML is the authoritative source.

## Signature incubator

Unverified discoveries belong in `signatures/incubator/`, not in the runtime
pack and never in C++. Incubator candidates preserve promising match logic and
source attribution but are excluded from compilation and verdicts. Promotion
requires plaintext and encrypted/metadata-visible coverage where applicable,
negative vectors, incremental-delivery tests and an explicit false-positive
boundary. See `signatures/incubator/README.md` for the complete workflow.

Rules may consume requestor-provided `flow.*` observations defined by
[API.md](API.md), but must name each accepted field explicitly. Flow metadata
must never be silently treated as raw-payload evidence, and requestor-provided
`payload.*` fields are reserved and ignored.

## Encrypted and inspected traffic

Whenever the available evidence makes it meaningful, a protocol or application
should have complementary signatures for both:

1. encrypted traffic, classified from observable encryption-layer metadata;
2. plaintext traffic, including content made available by TLS inspection.

The `enc.*` prefix is reserved exclusively for conclusions inferred without
access to the protected plaintext. A signature must not use `enc.*` merely
because the original connection used TLS or QUIC. The layer identifies the
encrypted evidence source, for example:

```text
enc.tls.app.youtube.video
enc.quic.app.youtube.video
```

Such rules may use evidence including SNI, ALPN, certificates, handshake
properties, and encryption-layer fingerprints. Their name must preserve that
the result is an inference from encrypted traffic rather than a classification
based on the protected application bytes.

Parsed application observations such as `flow.http1.*`, `flow.http2.*`, and
`flow.http3.*` are plaintext/L7 evidence. A rule based on HTTP headers,
authority, path, decoded content, or a validated HTTP subprotocol therefore
uses `protocol.*` or `app.*`, never `enc.*`. For example, a decoded
`application/dns-message` request is `protocol.doh`, while an ALPN-only DNS
inference remains `enc.tls.protocol.dns` or `enc.quic.protocol.dns`.

Plaintext signatures retain the existing namespaces without an inspection,
plaintext, or decrypted prefix:

```text
protocol.http2
app.youtube.video
```

It does not matter whether the plaintext was observed directly or supplied by
a TLS inspection component. If both encrypted-layer metadata and inspected
plaintext are available for one flow, both signature families may run and both
results may be reported. A plaintext match does not suppress the corresponding
`enc.*` match.

When plaintext is available, the signature pack should provide and prefer the
corresponding `protocol.*` or `app.*` result. It may additionally report an
`enc.*` result when independent encrypted-layer evidence also matches.
