# OWASP CRS - Plex Rule Exclusions Plugin

![Integration tests](https://github.com/davidscarth/plex-rule-exclusions-plugin/actions/workflows/integration.yml/badge.svg) ![Plugin lint](https://github.com/davidscarth/plex-rule-exclusions-plugin/actions/workflows/lint.yml/badge.svg)

## Description

Rule exclusions for [Plex Media Server](https://www.plex.tv/) behind an OWASP CRS 4.x reverse-proxy WAF (Coraza or ModSecurity). These remove the false positives that otherwise break playback, search, library filters, thumbnails, client log uploads, and artwork and subtitle uploads at paranoia level 1 (PL1). Every exclusion is scoped to one endpoint, and almost all to one parameter using `ctl:ruleRemoveTargetById`.

These started out as my own collection of hand-tuned WAF rules, and ran in production for over a year before I decided to share them with the community. My desire to share them led me to the OWASP CRS plugin registry, and I decided to make them into a formal plugin instead of a loose collection of rules.

This plugin makes Plex *work* behind CRS. To *harden* it, add [plex-hardening-plugin](https://github.com/davidscarth/plex-hardening-plugin), which builds on these exclusions with detection rules for CVE-2026-9665x and the Zenofex PoC classes, plus owner-only endpoint denies.

The CRS plugin documentation can be found on the [website]([https://coreruleset.org/docs/4-about-plugins/4-1-plugins/).

## Requirements

- OWASP CRS 4.25.2 or newer. Verified against 4.25.x (the CI harness's LTS target) and 4.30.0 (production, at PL1).
- ModSecurity 2.9 / 3.x or Coraza v3 (tested with coraza-caddy)

## How to install the plugin

Please see https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin

Copy the two files into the CRS `plugins/` directory:

```
plugins/plex-rule-exclusions-config.conf
plugins/plex-rule-exclusions-before.conf
```

## Deployment prerequisite

Plex clients use `PUT` and `DELETE` (`PUT /:/prefs`, `DELETE /activities/{id}`,
`PUT /log`). CRS 911100 allows only `GET HEAD POST OPTIONS` by default, so a
Plex deployment must either extend the list in `crs-setup.conf` (rule 900200):

```
SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST PUT DELETE OPTIONS'"
```

or not load `REQUEST-911-METHOD-ENFORCEMENT.conf` at all and enforce method
policy in front of the WAF (for example a Caddy `method` matcher with `abort`).
The CI harness keeps CRS's default method list, so the plugin tests avoid `PUT`/`DELETE`.

## Configuration

| Variable | Default | Config rule | Effect |
|---|---|---|---|
| `tx.plex-rule-exclusions-plugin_hosts` | unset | 9530023 | Scope the plugin to listed hosts and/or ports. Space-separated, slash-wrapped entries: `/name/` (any port), `/name:port/`, `/ip:port/`, or `/:port/` (any name on that port). Unset applies the plugin to every request. |

On a WAF dedicated to Plex, leave it unset, whether Plex is reached by domain, dynamic-DNS name or bare IP. A wrong value silently disables the exclusions for Plex and playback breaks, which is why unset is the default.

## Disabling the plugin

The plugin can be disabled by uncommenting rule 9530010 inside `plugins/plex-rule-exclusions-config.conf` or by removing the includes for this plugin.

## Rule ID map

The plugin uses the allocated block **9530000-9530999**, laid out per convention (000-099 initialization, 100-499 request rules, 500-999 response rules):

| Range | Purpose |
|---|---|
| `9530010` | Plugin disable switch (commented, in config) |
| `9530023` | Scope `SecAction` (commented, in config) |
| `9530089`-`9530093`, `9530096` | Scope flag default, tokens, flag, and gate (in before) |
| `9530099` | Plugin gate (removes 9530100-9530999) |
| `9530100`-`9530199` | Exclusions of CRS rules (phase 1); 9530100-9530180 in use |
| `9530200`-`9530499` | Unassigned (plex-hardening-plugin uses these suffixes for detection and denies, so the two merge by suffix) |
| `9530500`-`9530999` | Reserved for response rules |

## Rule exclusions

| Rule | Endpoint | Excluded target | From rule(s) | Why |
|---|---|---|---|---|
| 9530100 | `/video\|music\|audio\|subtitles/:/transcode/universal/*`, `/downloadQueue/{id}/add` | `ARGS:X-Plex-Client-Profile-Extra` | 932235, 932370 | client-profile DSL: `protocol=dash&` matches 932235, `&replace` in `add-limitation(...)` matches 932370 |
| 9530110 | `/photo/:/transcode` | `ARGS:url` (loopback URLs only) | 931100, 934110 | thumbnails are fetched via `url=http://127.0.0.1:32400/...` |
| 9530120 | `/log` | `ARGS:message` | 932370 | client log lines are free text |
| 9530130 | `/media/grabbers/devices`, `/media/grabbers/tv.plex.grabbers.hdhomerun/devices…` | `ARGS:uri` | 931100 | tuner LAN address (moot if plex-hardening-plugin's endpoint denies are on) |
| 9530140 | `/library/search`, `/tv.plex.providers.*/library/search` | `ARGS:query` | 932230, 932250 | free-text search matches wrapper + 2-3 char command shape (932230) and direct command shape, including type-ahead fragments like `sh movie` (932250) |
| 9530150 | `/status/sessions/terminate` | `ARGS_NAMES:sessionId` | 943110, 943120 | playback key, not an auth session; endpoint is owner-only |
| 9530160 | `/library/sections/{id}/all` | whole rule (`ctl:ruleRemoveById`; a regex target key does not load on libmodsecurity) | 932250 | Advanced Filters: free text in the Title field (any level prefix, any operator form) matches the direct command shape, e.g. `title!=ls` |
| 9530170 | `POST /library/metadata/{id}/{posters,arts,clearLogos,squareArts,...}` | request body not read (`ctl:requestBodyAccess=Off`) | 920250 | artwork uploaded from a file is a raw image body sent under a form content type, so the engine parses it as form fields and 920250 (when enabled) rejects the bytes; an image is not form data |
| 9530180 | `POST /library/metadata/{id}/subtitles` | `REQUEST_HEADERS:Content-Type` on 920420; request body not read | 920420 | subtitle files are posted as `text/plain`, which the CRS content-type policy does not allow; the body would then be parsed as form fields like artwork |

## How rules are added

Sources, in order of precedence:

1. **Observed traffic.** An exclusion is added or widened when a real client is seen tripping a CRS rule. Observation overrides the specs where they differ (e.g. Plex Web sends `GET /updater/check`; the spec documents `PUT`).
2. **Current Plex OpenAPI spec**, v1.2.3, https://developer.plex.tv/pms/. Used to confirm what an endpoint and parameter are for, and to widen an exclusion only along a same-input axis: the same parameter with the same content arriving by another documented door (an enum sibling of a path segment, a second documented endpoint for the same parameter, another spelling of the same filter operator).
3. **Historical Plex developer docs** (pre-OpenAPI). Used to explain observed behavior the current spec omits (e.g. the grabber-proxied `/devices/probe?uri=` path). Never used to widen an exclusion.

Each exclusion's comment records the evidence: endpoint, parameter, CRS rule ID, date, CRS version.

### Observed deltas from the spec

Where real traffic differed from the Plex OpenAPI spec (v1.2.3), the rules follow the traffic. Recorded so the next person does not "correct" them back to the spec:

| Observed | Spec | Rule |
|---|---|---|
| Artwork is uploaded to plural `/posters`, `/arts`, `/clearLogos`, `/squareArts`, as raw bytes under a form content type | singular `{element}` (`poster`, `art`, …); content type not stated | 9530170 |
| Subtitle upload is a `POST` with `Content-Type: text/plain` | endpoint documented as `GET` only | 9530180 |
| Photo transcoder `url=` is an absolute loopback URL, port copied from the client's connection (`:32400`, `:443`) | relative path example only | 9530110 |
| Plex Web encodes filter operators inconsistently (`title!=x` and `title!%3D=x` for the same operator), so the parsed parameter name varies | operators documented, encoding not | 9530160 |
| Plex Web and other clients search via `/library/search` | only `/hubs/search` documented | 9530140 |
| Tuner add goes through the server-proxied grabber path `/media/grabbers/tv.plex.grabbers.hdhomerun/devices` | bare `/media/grabbers/devices` | 9530130 |
| The profile verb `add-transcode-target-settings(...)` is accepted by the server | absent from the official augmentation grammar | 9530100 (and hardening 9531220) |
| Plex Web calls `GET /updater/check` | documented as `PUT` | hardening 9531430 (method-agnostic for this reason) |
| Android TV polls `GET /transcode/sessions/{id}` during playback | endpoint not documented | hardening 9531480 |
| `POST /library/sections/refresh` returns 404 on PMS 1.43.4; the per-section form works | documented | none |
| Legacy `/library/hashes` returns 404 on PMS 1.43.4 | not in the spec; in the legacy docs | none (hardening 9531200 note) |

## Tags

The plugin's rules are `pass,nolog` exclusions and carry no tags. To disable one on a path, use its ID: `ctl:ruleRemoveById=9530140`. All exclusions are `ruleRemoveTargetById` on one parameter except 9530160, which removes 932250 on its one endpoint because libmodsecurity will not load a regex target key, and the two upload rules, which stop the body being read.

## Testing

Tests use the go-ftw YAML format under `tests/regression/plex-rule-exclusions-plugin/`, one file per rule, and run through the shared [crs-plugin-test-action](https://github.com/coreruleset/crs-plugin-test-action) workflows (`.github/workflows/integration.yml`, `lint.yml`). That pipeline runs Apache + ModSecurity 2 and nginx + ModSecurity 3 in `DetectionOnly` at paranoia level 4 against CRS `main` and the current LTS.

Every test's payload was checked against the CRS 4.29.0 regex of the rule it targets, so the `no_expect_ids` assertion only holds because the exclusion is in place, and every file except 9530170 also has a scope-control case on an unrelated path asserting the CRS rule still fires. Positive cases also carry `no_match_regex` over paranoia-level-1 rule IDs, so a CRS rule added later that matches the same legitimate payload fails the test; because the harness is `DetectionOnly`, a response-status assertion would prove nothing.

## Reporting false positives

If you find a false positive that this plugin does not cover then please open a new issue or pull request, including:

1. CRS version
2. ModSecurity / Coraza version
3. WAF audit or error log lines for the request
4. The Plex client and action that caused it

## License

Apache-2.0
