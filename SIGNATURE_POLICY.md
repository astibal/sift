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

Rules may consume requestor-provided `flow.*` observations defined by
[API.md](API.md), but must name each accepted field explicitly. Flow metadata
must never be silently treated as raw-payload evidence, and requestor-provided
`payload.*` fields are reserved and ignored.
