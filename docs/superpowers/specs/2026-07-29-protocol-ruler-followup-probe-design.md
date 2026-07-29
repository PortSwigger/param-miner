# Protocol ruler follow-up probe on discovered headers

**Date:** 2026-07-29
**Status:** implemented

## Goal

When Param Miner discovers a header, find out whether a front-end is rewriting
it.

Param Miner's header discovery is diff-based: a header only surfaces if it causes
an observable response difference. That tells you the header is honoured
somewhere, but nothing about whether something between you and the application
is trimming, expanding, replacing or truncating on it. The "protocol ruler"
size-cliff oracle answers that question without needing any observable
difference at all, which makes it a natural follow-up on each discovered header.

## Mechanism

Every proxy/server has a maximum header length; crossing it flips the response
status. That cliff is a precise byte-count oracle. Pad the target header up to
the cliff, binary-search where the cliff *actually* lands, and
`transformation = expectedCliff − actualCliff` is the signed byte delta between
what was sent and what the server saw. Nonzero ⇒ something rewrote the header,
and the sign gives the direction.

Result taxonomy: `NO_CHANGE`, `EXPAND` (lengthened), `SHRINK` (trimmed),
`OVERWRITE` (removed/replaced), `BLOCKED` (rejected), `TERMINATED` (truncated
after the header), `INCONSISTENT`. `isInteresting()` is `>= OVERWRITE`, so
OVERWRITE / EXPAND / SHRINK / TERMINATED report; NO_CHANGE, BLOCKED and
INCONSISTENT do not.

See https://portswigger.net/research/http-terminator#protocol-ruler

## Request cost

`analyseTransformation` fires two quick probes first and returns after ~3
requests when the header isn't transformed, so the expensive path (6-step binary
search + 11×2 confirmation loop + truncation check) only runs on a real hit.

| | requests |
|---|---|
| Calibration (`getMax` + `confirmServerLimit`), once per attack | ~36 |
| Per header, not transformed — the common case | ~9 |
| Per header, all three probes transformed | ~96 |
| No-cliff target, whole attack | ~36, then silent |

The dominant cost is the one-time calibration, and it is only paid once a header
has actually been found. Hence default-on.

## Files

| File | Role |
|------|------|
| `ProxyServer.java` | The oracle. Calibrates the size limit, measures the cliff, classifies the delta. |
| `ProxyProbe.java` | One padded probe: header, injection type, pad arithmetic. |
| `ProxyTransformationResult.java` | Result model, taxonomy, description rendering. |
| `HeaderRuler.java` | Stateless driver. Single entry point `probe(ParamAttack, String)`. |
| `ParamAttack.java` | `+ ruler` / `rulerInitialised` fields, `getRuler()`, `disableRuler()` |
| `ParamGuesser.java` | Passes `state` into the `DiscoveredParam` constructor (1 line, single call site) |
| `DiscoveredParam.java` | `+ attack` field; gated call in `explore()` |
| `BurpExtender.java` | +1 setting, version bump |

## Probe set (per discovered header)

Three `VALUE_APPEND` probes against the discovered header's own name, taken from
`name.split("~", 2)[0]` to strip any `~value` suffix:

```java
HttpHeader.httpHeader(headerName, "wrtz")             // is it rewritten at all
HttpHeader.httpHeader(headerName, "X-AAA\0AAA-X")     // null byte in value
HttpHeader.httpHeader(headerName, "X-AAA\rfoo:AAA-X") // raw CR in value
```

The two char-level probes are the non-reflective counterpart to
`ValueProbes.urlDecodes` / `eatsBackslash` / `utf8` — they catch value
transformations that never surface in the response.

## Oracle lifetime

One `ProxyServer` per `ParamAttack`, lazily calibrated on the first discovered
header. Targets where no header is ever found never pay for it; targets with no
usable cliff pay once and then go silent. No locking — `guessParams` is
single-threaded per attack.

Rejected alternatives: per-discovered-header (re-pays ~36 requests every time,
re-discovers `badTarget` every time) and a static per-host cache (needs
thread-safety for the 8-thread pool, and the limit can legitimately differ per
endpoint).

## Inconsistency policy

A `null` or `INCONSISTENT` result means the cliff isn't stable, which makes every
later measurement suspect. `disableRuler()` retires the oracle for the remainder
of the attack, capping waste on a flaky target at ~125 requests.

`server.badTarget` is checked alongside the result because `confirmServerLimit`
can set it *after* `analyseTransformation`'s own entry check has passed;
`ProxyServer` returns a garbage result in that window rather than bailing, so
`HeaderRuler` has to catch it.

## Reporting

The ruler self-reports, mirroring `ValueProbes.transformation()`. The existing
"Secret input: header" issue is untouched — no new tag — because the finding is
only interpretable with its cliff request pairs attached:

- `Scan.report(...)` with `justUnder` / `justOver` attached, plus the
  reference link.
- Both pairs annotated and sent to the Organizer.
- `wayUnder` / `wayOver` are **not** attached: `ProxyServer` never populates
  them. `justOver` is null for an OVERWRITE, so nulls are filtered and reporting
  is skipped if no evidence survives.

## Gating and placement

New setting, default on:

```java
guessSettings.register("probe header transformations", true,
    "After discovering a header, use the protocol ruler size-cliff oracle to "
  + "detect front-end rewriting. Needs HTTP/1.1 and sends requests padded to "
  + "the server's max header size.");
```

The call sits in `explore()` after the cheap reflection probes but *before* the
`scan identified params` early return — otherwise it would never run, since that
setting defaults false. It has its own try/catch so a ruler failure can't stop
the later `ParamScan` and active-scan blocks.

## Build note

Use `./gradlew build fatJar`, as `BappManifest.bmf` specifies — the order
matters. `build` alone runs the plain `jar` task, which bundles none of the
dependencies and produces an unloadable ~559 KB artifact; only `fatJar` produces
the loadable ~8.9 MB extension. Both resolve to the same
`build/libs/param-miner-all.jar` filename, because `fatJar`'s `baseName`
override is commented out, so running `build` *after* `fatJar` silently replaces
a working extension with a broken one. Size is the tell.

## Verification

- `./gradlew fatJar` succeeds; `HeaderRuler.class` present in
  `param-miner-all.jar` alongside its bundled dependencies.
- Signatures confirmed against `bulkScan-all.jar` (the gradle dependency; the
  root `bulkScan.jar` is stale and disagrees): `MontoyaRequestResponse
  implements HttpRequestResponse`, and `Scan.report(String, String, byte[],
  HttpRequestResponse...)` is static, so reachable from a non-`Scan` class.
- **Not yet done:** run against a known transforming front-end to confirm
  EXPAND/SHRINK/OVERWRITE fire, and that a discovered header on a no-cliff
  target logs the skip message once and stays quiet.
