# Signature Incubator

The incubator is Sift's evidence-preserving backlog of plausible signatures.
Its contents are deliberately **not compiled into `siftd`** and must never
affect a runtime verdict.

The initial inventory was imported from the former local
`smithproxy-signature-pack` research repository. Of its 150 entries, 19 were
already represented by production rules and were removed during import. The
remaining 131 candidates retain pinned upstream references. The candidate
schema is intentionally richer than the current runtime schema so that
transport, confidence, provenance and unfinished matching ideas survive
refinement.

```text
upstream evidence
       |
       v
incubator candidate  -- review/refine/test -->  signatures/default.yaml
       ^                                             |
       |                                             v
       +---------- remains inert                 siftd runtime
```

## Promotion checklist

A candidate may leave the incubator only when one production signature (or a
small related family) is added to `../default.yaml` and all of the following
are true:

1. Its stable identifier, direction and protocol layer are unambiguous.
2. Primary evidence is content-based; addresses and ports are hints only.
3. Plaintext positive and relevant negative vectors exist when plaintext is
   observable.
4. The encrypted/metadata-visible variant is covered when one exists (for
   example SNI, ALPN, DNS or trusted decoded-flow observations). If encryption
   makes identification impossible, that limitation is written down instead
   of inventing a weak detector.
5. Fragmentation and incremental flow delivery are tested where applicable.
6. False-positive boundaries and confidence are documented.
7. Upstream project and pinned source URL remain attributable.
8. Pack compilation and the complete Sift test suite pass.

After promotion, remove the candidate from its incubator pack in the same
commit. A candidate must not silently exist in both places: either the
production rule supersedes it, or the incubator entry explains the remaining
unpromoted variant.

## Files

- `core.yaml` -- common protocol and transport candidates;
- `protocols-extra.yaml` -- additional protocol candidates;
- `services.yaml` -- application/service and hostname candidates;
- `content.yaml` -- file and embedded-content candidates;
- `UPSTREAMS.yaml` -- pinned provenance for the imported inventory.

`tools/validate_incubator.py` checks structural integrity, unique identifiers
and source attribution. Validation does not imply production quality.
