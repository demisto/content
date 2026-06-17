# Demo: `check_auth_parity.py`

Copy-paste runnable from the repo root. Each case shows the command and
the expected per-connection `status`.

## Setup

```bash
cd /Users/juschwartz/dev/content
docker info >/dev/null && echo "Docker OK"   # required for all run cases
export DEMISTO_SDK_LOG_FILE_PATH=.sdk-logs/sdk.log
mkdir -p .sdk-logs
```

The `DEMISTO_SDK_LOG_FILE_PATH` redirect avoids a macOS data-protection
issue where the SDK can't write to its default log path
(`~/.demisto-sdk/logs/`), which crashes `prepare-content` and surfaces
as an opaque `inconclusive` with empty captures.

---

# Per-param value seeding via `--seed-param`

By default the harness auto-generates a `SENTINEL_PARAM_<name>` value
for every YML param so it can grep for them on the wire. When such an
auto-generated value trips a format validator at module import or in
`Client.__init__` (cert thumbprints, JWT secrets with format checks,
OIDC issuer URLs, enum-value selectors like Case 5's
`authentication_type`), both runs crash before any HTTP request and
the connection lands as `inconclusive`. The fix is to pin a real value
with `--seed-param`:

- **Repeatable:** each `--seed-param NAME=VALUE` appends to a dict;
  pass it multiple times for multiple params.
- **Traceable sentinel:** any value ≥4 characters appears verbatim in
  the captured HTTP, so a seeded value still acts as a grep target.
- **Dotted-leaf for `type: 9` credentials:** use
  `--seed-param creds.identifier=<value>` and
  `--seed-param creds.password=<value>` to seed each leaf
  independently.
- **Flat-on-`type: 9` is rejected:** a flat
  `--seed-param creds=<value>` against a `type: 9` widget exits with
  code `2` and an actionable error pointing at the dotted-leaf form.
  Stray dotted-leaf overrides against non-`type: 9` params surface as
  `[seed] WARNING` lines on stderr (non-fatal).

Auto-coerced params (cert / thumbprint / private_key) usually don't
need `--seed-param` — built-in coercion handles them. The flag is for
the auto-coercion's blind spots. See
[`connectus/connectus-migration-SKILL.md`](connectus/connectus-migration-SKILL.md:1)
§1.12 for the full skill-level worked-examples doc.

---

# PASS cases (zero code changes)

## Case 1 — PASS: APIKey, Bearer header (Tavily)

`Tavily.py` sets `Authorization: Bearer <api_key>` in `Client.__init__`
— matches the default UCP `_apply_ucp_api_key` wire shape.

```bash
python3 connectus/check_auth_parity.py \
    Packs/Tavily/Integrations/Tavily \
    --integration-id Tavily \
    --auth-details '{"auth_types":[{"type":"APIKey","name":"credentials","xsoar_param_map":{"api_key":"key"}}],"other_connection":["insecure","proxy","url"]}'
```

**Expected:** `auth_parity.credentials.status == "pass"`, sentinel lands
at `POST /extract header:authorization:bearer` in both runs.

---

## Case 2 — PASS: APIKey, Bearer header (PenfieldAI)

Same pattern as Tavily, different YML param name (`apikey`).

```bash
python3 connectus/check_auth_parity.py \
    Packs/PenfieldAI/Integrations/Penfield \
    --integration-id Penfield \
    --auth-details '{"auth_types":[{"type":"APIKey","name":"credentials","xsoar_param_map":{"apikey":"key"}}],"other_connection":["insecure","proxy","url"]}'
```

**Expected:** `auth_parity.credentials.status == "pass"`, sentinel lands
at `GET /api/v1/xsoar_live_assign/ header:authorization:bearer` in both
runs.

---

## Case 3 — PASS: Plain, HTTP Basic (NutanixHypervisor)

`NutanixHypervisor.py` passes `auth=(username, password)` to
`BaseClient.__init__` — matches the default UCP `_apply_ucp_plain` wire
shape. Both username and password slots compared after base64-decoding
the `Authorization: Basic …` header.

```bash
python3 connectus/check_auth_parity.py \
    Packs/NutanixHypervisor/Integrations/NutanixHypervisor \
    --integration-id NutanixHypervisor \
    --auth-details '{"auth_types":[{"type":"Plain","name":"credentials","xsoar_param_map":{"credentials.identifier":"username","credentials.password":"password"}}],"other_connection":["base_url","insecure","proxy"]}'
```

**Expected:** `auth_parity.credentials.status == "pass"`. Two sentinels
land at:
- `GET /PrismGateway/services/rest/v2.0/alerts header:authorization:basic:user`
- `GET /PrismGateway/services/rest/v2.0/alerts header:authorization:basic:pass`

---

# FAIL cases

## Case 4 — FAIL: APIKey lands at custom header (APIVoid)

Real integration, real Auth Details from the pipeline CSV. `APIVoid.py`
sets `headers = {"X-API-Key": apikey}` — secret lands at `X-API-Key`.
Default UCP `_apply_ucp_api_key` puts the same secret at
`Authorization: Bearer`. Different wire location → `WRONG_LOCATION`.

```bash
python3 connectus/check_auth_parity.py \
    Packs/APIVoid/Integrations/APIVoid \
    --integration-id APIVoid \
    --auth-details '{"auth_types":[{"type":"APIKey","name":"credentials","xsoar_param_map":{"credentials.password":"key"}}],"other_connection":["insecure","proxy","url"]}'
```

**Expected:** `auth_parity.credentials.status == "fail"` with one diff:
```
failure_code: WRONG_LOCATION
old_locations: ["POST /v2/ip-reputation header:x-api-key"]
new_locations: ["POST /v2/ip-reputation header:authorization:bearer"]
```

**Skill action:** override `_apply_ucp_api_key` in `Client` to set
`X-API-Key` (preferred fix), or mark the entry `"interpolated": true`
as last resort.

---

## Case 5 — Mixed verdict: requires source-code change to model cleanly (TeamCymruScout)

`TeamCymruScout` exposes a `type: 15` selector
[`authentication_type`](Packs/TeamCymru/Integrations/TeamCymruScout/TeamCymruScout.yml:16)
with two options — `API Key` and `Basic Auth` — and the integration's
[`main()`](Packs/TeamCymru/Integrations/TeamCymruScout/TeamCymruScout.py:1241)
branches on it: the `Basic Auth` path builds `auth=(username, password)`
(matches UCP `_apply_ucp_plain` default → would pass parity), while the
`API Key` path builds `headers["Authorization"] = f"Token {api_key}"`
— a non-`Bearer` prefix that diverges from UCP `_apply_ucp_api_key`'s
default `Authorization: Bearer <key>` → fails parity with
`WRONG_LOCATION`.

This is the canonical case where the integration's existing code shape
mixes a clean canonical-profile flow with one that needs a UCP override
to round-trip the secret to the right slot. As-is, classifying this
integration as two `auth_types[]` entries (one `Plain` + one `APIKey`)
will produce a mixed verdict in a single set of parity runs — useful
diagnostically but not a sustainable production classification without
the code change below.

```bash
# Basic Auth run
env -u ALL_PROXY -u all_proxy -u FTP_PROXY -u ftp_proxy \
python3 connectus/check_auth_parity.py \
    Packs/TeamCymru/Integrations/TeamCymruScout \
    --integration-id "Team Cymru Scout" \
    --connection basic_auth \
    --seed-param authentication_type='Basic Auth' \
    --auth-details '{"auth_types":[{"type":"APIKey","name":"api_key","xsoar_param_map":{"api_key.password":"key"}},{"type":"Plain","name":"basic_auth","xsoar_param_map":{"basic_auth.identifier":"username","basic_auth.password":"password"}}],"other_connection":["authentication_type","insecure","proxy"]}'

# API Key run
env -u ALL_PROXY -u all_proxy -u FTP_PROXY -u ftp_proxy \
python3 connectus/check_auth_parity.py \
    Packs/TeamCymru/Integrations/TeamCymruScout \
    --integration-id "Team Cymru Scout" \
    --connection api_key \
    --seed-param authentication_type='API Key' \
    --auth-details '{"auth_types":[{"type":"APIKey","name":"api_key","xsoar_param_map":{"api_key.password":"key"}},{"type":"Plain","name":"basic_auth","xsoar_param_map":{"basic_auth.identifier":"username","basic_auth.password":"password"}}],"other_connection":["authentication_type","insecure","proxy"]}'
```

The harness runs each `auth_types[]` entry independently. You will
likely need to pin the in-code selector per-run so the integration's
branching exercises the right path; pass `--connection basic_auth
--seed-param authentication_type='Basic Auth'` for the Plain run and
`--connection api_key --seed-param authentication_type='API Key'` for
the APIKey run. Without the pin, one of the two will trip
[`validate_params`](Packs/TeamCymru/Integrations/TeamCymruScout/TeamCymruScout.py:246)
on the wrong-cred slot being empty and yield `inconclusive` instead of
the expected pass/fail.

**Expected:**
```
auth_parity.basic_auth.status  == "pass"   (auth=(user,pass) matches _apply_ucp_plain default)
auth_parity.api_key.status     == "fail"   (Authorization: Token diverges from default Bearer)
```

The `api_key` diff shows `WRONG_LOCATION`:
- `old_locations: ["GET /usage header:authorization:token"]`
- `new_locations: ["GET /usage header:authorization:bearer"]`

**Skill action:** the integration needs a source-code change to be
sustainably classified as two clean canonical profiles. Override
`_apply_ucp_api_key` on `Client` to write the API key into
`Authorization: Token <key>` instead of accepting UCP's default
`Authorization: Bearer <key>` (worked example pattern documented in
the connectus-migration skill, §Step 6 "UCP support for integrations
using non-standard auth headers"). Once the override is in place, both
parity verdicts pass and the two-profile classification is stable.
As an interim alternative, mark the `api_key` entry
`"interpolated": true` — the parity tool will then auto-N/A that
connection and the workflow advances on the `basic_auth` connection
alone.

---

# Inconclusive cases (analyzer ran, but couldn't compare)

## Case 6 — `inconclusive`: pre-flight URL validation rejects proxy (WorkdaySignOnEventCollector)

`Client.__init__` raises if `base_url` doesn't start with `https://`,
but the harness rewrites `base_url` to `http://127.0.0.1:NNNN`. Both
runs crash before any HTTP request.

```bash
python3 connectus/check_auth_parity.py \
    Packs/Workday/Integrations/WorkdaySignOnEventCollector \
    --integration-id WorkdaySignOnEventCollector \
    --auth-details '{"auth_types":[{"type":"Plain","name":"credentials","xsoar_param_map":{"credentials.identifier":"username","credentials.password":"password"}}],"other_connection":["base_url","insecure","proxy"]}'
```

**Expected:** `auth_parity.credentials.status == "inconclusive"` with
`RUN_FAILED_OLD` and `RUN_FAILED_NEW` diffs. `stderr_excerpt` shows
`Invalid base URL. Should begin with https://`.

**Skill action:** the integration genuinely rejects the harness's
proxy URL — mark `interpolated: true`.

---

## Case 7 — `inconclusive`: `test-module` raises without HTTP (HPE Aruba Central)

`test_module()` raises `DemistoException` unconditionally because
Aruba's API rate-limits access-token regeneration. Both runs crash
inside `test-module` before any HTTP request is issued → empty captures.

```bash
python3 connectus/check_auth_parity.py \
    Packs/HPEArubaCentral/Integrations/HPEArubaCentralEventCollector \
    --integration-id HPEArubaCentralEventCollector \
    --auth-details '{"auth_types":[{"type":"Passthrough","name":"credentials","xsoar_param_map":{"client_credentials.identifier":"client_id","client_credentials.password":"client_secret"},"interpolated":true}],"other_connection":["base_url","insecure","proxy"]}'
```

**Expected:** `auth_parity.credentials.status == "inconclusive"` with
diffs containing `RUN_FAILED_OLD`, `RUN_FAILED_NEW`, and per-sentinel
`MISSING_IN_BOTH`. `stderr_excerpt` shows the integration's
`"Test module is not available … Use the aruba-auth-test command
instead."` message. Override `--commands aruba-auth-test` to actually
exercise auth.

---

# Skip cases (analyzer refused to run that connection)

## Case 8 — `ERROR_ALL_INTERPOLATED` (exit 12, no Docker needed)

Every `auth_types[]` entry has `"interpolated": true` → step is
vacuously migrated. Short-circuits before any container boots.

```bash
python3 connectus/check_auth_parity.py \
    Packs/APIVoid/Integrations/APIVoid \
    --integration-id APIVoid \
    --auth-details '{"auth_types":[{"type":"APIKey","name":"credentials","interpolated":true,"xsoar_param_map":{"credentials.password":"key"}}],"other_connection":["insecure","proxy","url"]}'
echo "exit=$?"
```

**Expected:** exit `12`, `error.code == "ERROR_ALL_INTERPOLATED"`,
message contains literal `Mark its auth as interpolated`.

---

## Case 9 — `skipped_signed`: EdgeGrid (Akamai WAF)

Imports `EdgeGridAuth` → harness can't follow secrets through the
derived HMAC signature. Akamai_WAF has a `BaseClient` subclass (so the
ERROR_NO_BASECLIENT gate clears), but the signed-auth import then
trips the per-connection skip.

Note: AWS-* integrations would seem like the canonical "signed" example
but they typically don't subclass `BaseClient` directly, so they fail
the earlier `ERROR_NO_BASECLIENT` gate (exit 11) before `skipped_signed`
ever fires.

```bash
python3 connectus/check_auth_parity.py \
    Packs/Akamai_WAF/Integrations/Akamai_WAF \
    --integration-id "Akamai WAF" \
    --auth-details '{"auth_types":[{"type":"APIKey","name":"credentials","xsoar_param_map":{"credentials.password":"key"}}],"other_connection":["host","insecure"]}'
```

**Expected:** `auth_parity.credentials.status == "skipped_signed"`.
Sentinels never land verbatim because the wire signature is an HMAC of
the request — not the secret itself.

---

## Case 10 — `skipped_mtls`: certificate auth (SAP BTP)

YML has a `type: 14` cert config param (`private_key` — "Required for
mTLS authentication") → mTLS handshake can't be sentinel-grepped.
SAP_BTP also subclasses `BaseClient`, so the ERROR_NO_BASECLIENT gate
clears and the per-connection `skipped_mtls` skip is what surfaces.

```bash
python3 connectus/check_auth_parity.py \
    Packs/SAP_BTP/Integrations/SAPBTP \
    --integration-id SAPBTP \
    --auth-details '{"auth_types":[{"type":"Passthrough","name":"credentials","xsoar_param_map":{"credentials.identifier":"client_id","credentials.password":"client_secret"},"interpolated":true}],"other_connection":["host","insecure"]}'
```

**Expected:** `auth_parity.credentials.status == "skipped_mtls"`.

---

# Hard errors (exit non-zero before any run)

## Case 11 — `ERROR_NO_BASECLIENT` (exit 11): direct `requests` use (WhatIsMyBrowser)

Python integration but uses `requests.request()` directly with no
`BaseClient` subclass. The harness has no `_apply_ucp_*` seam to mock.

```bash
python3 connectus/check_auth_parity.py \
    Packs/WhatIsMyBrowser/Integrations/WhatIsMyBrowser \
    --integration-id WhatIsMyBrowser \
    --auth-details '{"auth_types":[{"type":"APIKey","name":"credentials","xsoar_param_map":{"credentials_api_key.password":"key"}}],"other_connection":[]}'
echo "exit=$?"
```

**Expected:** exit `11`, `error.code == "ERROR_NO_BASECLIENT"`,
message contains literal `Mark its auth as interpolated`. No Docker
required.

---

## Case 12 — `ERROR_NON_PYTHON` (exit 10): JavaScript integration (AlgoSec)

```bash
python3 connectus/check_auth_parity.py \
    Packs/Algosec/Integrations/AlgoSec \
    --integration-id AlgoSec \
    --auth-details '{"auth_types":[{"type":"Plain","name":"credentials","xsoar_param_map":{"credentials.identifier":"username","credentials.password":"password"}}],"other_connection":["insecure","server"]}'
echo "exit=$?"
```

**Expected:** exit `10`, `error.code == "ERROR_NON_PYTHON"`. No Docker
required — language check happens at YML parse time.

---

# Reading the output

| `auth_parity.<conn>.status` | Meaning |
|---|---|
| `pass` | Every sentinel landed in the same locations on both runs. |
| `fail` | At least one diff (see `diffs[].failure_code`). |
| `inconclusive` | Captured no requests on one or both sides. |
| `skipped_interpolated` | Connection is `interpolated: true`. |
| `skipped_signed` | Integration imports `hmac` / `botocore` / `AWSApiModule` / `EdgeGridAuth`. |
| `skipped_mtls` | YML has `type: 14` (certificate) auth slot. |
| `skipped_passthrough` | Auth type classified as `Passthrough` — the analyzer has no standardized UCP credential shape to inject. |

| `diffs[].failure_code` | Meaning |
|---|---|
| `WRONG_LOCATION` | Sentinel present in both runs but at different locators. |
| `MISSING_IN_NEW` | Sentinel present old-side only; UCP injection lost it. |
| `EXTRA_IN_NEW` | Sentinel present new-side only; UCP added a placement. |
| `MISSING_IN_BOTH` | Sentinel showed up nowhere. |
| `RUN_FAILED_OLD` / `RUN_FAILED_NEW` | Child crashed before issuing requests. |
| `NO_REQUESTS_CAPTURED` | Child ran cleanly but never hit the proxy. |

| Exit code | Meaning |
|---|---|
| `0` | Ran to completion (parity verdict in stdout JSON). |
| `2` | Bad CLI input. |
| `3` | Unhandled exception in analyzer. |
| `10` | `ERROR_NON_PYTHON`. |
| `11` | `ERROR_NO_BASECLIENT`. |
| `12` | `ERROR_ALL_INTERPOLATED`. |
| `13` | `ERROR_CONNECTION_INTERPOLATED`. |
| `14` | `ERROR_INTEGRATION_REJECTS_HTTP`. |
