# OSPF Watcher Release Notes v3.2.0

> [!IMPORTANT]
> **Before pulling this version, update your Logstash and Fluent Bit schemas.**
> This release adds a new **SRLG** field to OSPF TE-metric events. The
> watcher image (`vadims06/ospf-watcher:v3.2.0`) emits the new field, so the
> pipeline that parses watcher logs must be updated **at the same time**, or
> events carrying SRLG will fail to parse / drop the field.
>
> Pull the matching schema files from this repo together with the image:
> - `logstash/` — pipeline filters and index templates
> - `fluentbit/` — `fluent-bit.yaml` parser/pipeline
>
> Recommended order: stop the stack → pull the new image **and** the updated
> `logstash/` + `fluentbit/` files → start the stack.

## New features

**SRLG (Shared Risk Link Group) visualization and tracking**
The watcher now reads SRLG membership from the OSPF TE opaque-area LSA
(RFC 4203, Type 10, TLV 22 sub-TLV 138) and tracks changes over time:
- Supported in both GRE and BGP-LS modes.
- SRLG **added / removed / changed** on a link is folded into the existing
  **TE-metric change event** (alongside metric / bandwidth), so no new event
  type is introduced — existing alerting keys continue to work once the
  pipeline schema is updated.

**OSPF max-metric (stub router, RFC 3137) node flag**
The watcher detects when a router advertises max-metric (stub-router
advertisement) and emits a `node,changed,attr:maxmetric` event on each
transition. The flag is seeded from the initial OSPF database at startup so
a router already in stub-router mode at startup does not generate a spurious
change event.

**ABR / ASBR node flag change tracking** *(watcher image ≥ v3.1.6)*
The watcher tracks OSPF Router-LSA node flags — B (Area Border Router) and
E (AS Boundary Router) — and emits a `node,changed` event on each per-router
transition. Flags are parsed in both GRE mode (Router-LSA flags, on-wire and
from the initial database) and BGP-LS mode (Node Flag Bits).

## Version → features

| Version | New features |
|---------|--------------|
| v3.0.0  | BGP-LS mode — receive OSPF topology via BGP-LS (GoBGP forwarder) |
| v3.1.0  | Fluent Bit profile and pipeline; watcher heartbeat compatible with Topolograph 2.63 |
| v3.1.1  | Loki output for Logstash and Fluent Bit |
| v3.1.5  | Loki output; `node,changed` (ABR/ASBR) event parsing in Logstash + Fluent Bit |
| v3.1.6  | ABR/ASBR node-flag baseline seeded from the initial OSPF database; `node,changed` events emitted by the watcher image |
| **v3.2.0** | **SRLG visualization & tracking — OSPF (RFC 4203 TLV 22 sub-TLV 138), GRE + BGP-LS; SRLG changes folded into the TE-metric event. OSPF max-metric (stub router) node flag + `node,changed` events. Requires updated Logstash + Fluent Bit schemas.** |
