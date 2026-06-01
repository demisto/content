# Darkmon

Real-time threat intelligence from the Clear, Deep, and Dark Web. Enrich
indicators, hunt compromised credentials, monitor VIP emails, track ransomware
mentions, watch newly registered domains, and ingest the IOC feed into TIM.

## Configure

| Field | Required | Notes |
|---|---|---|
| **API Base URL** | No | Defaults to production. Override per-instance to point at a dev/staging environment. |
| **API key** | **Yes** | Paste the X-API-KEY value from your Darkmon tenant. |
| **Trust any certificate** | No | Leave off in production. |
| **Use system proxy settings** | No | Toggle if your XSOAR engine routes outbound through a proxy. |
| **Indicator Reputation** | No | Default reputation applied to indicators fetched from the feed. |
| **Source Reliability** | No | A-F per Admiralty code; defaults to F. |
| **Indicator expiration / interval / fetch interval / bypass exclusion list** | No | Standard XSOAR feed settings. |
| **Traffic Light Protocol Color** | No | Stamps fetched indicators with the chosen TLP. |
| **Tags** | No | Comma-separated tags applied to every fetched indicator. |
| **Indicator fetch limit** | No | Max indicators per fetch cycle. Default 1000. |
| **Redact secrets in War Room** | No | Default `true`. Replaces passwords/card numbers in markdown output with `***`. Raw values remain in `rawJSON`. |

## Commands

- `!test-module` — auth check
- `!ip` / `!url` / `!domain` / `!email` / `!file` — reputation enrichment, populates `DBotScore` and `Common.<Type>`
- `!dmontip-global-search` — fully dynamic search across every Darkmon data type
- `!dmontip-get-indicators` — pull the latest IOC feed
- `!dmontip-get-compromised type=accounts|bank-cards|combo-lists|public-breaches|employees`
- `!dmontip-get-vpn` / `!dmontip-get-proxy` / `!dmontip-get-cve`
- `!dmontip-get-nrd` / `!dmontip-get-tbf`
- `!dmontip-get-ransomware type=mentions|all-topics`
- `!dmontip-get-landscape type=mentions|all-topics`
- `!dmontip-get-boardprotection`
- `!dmontip-get-boardemails type=accounts|combo-lists|public-breaches email=<email>`

Default sort is newest-first where applicable (`firstSeen,desc`,
`timestamp,desc`, `publishedAt,desc`); override with the `sort` argument.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `test-module` 401 | Wrong API key or expired | Re-paste from Darkmon admin |
| `test-module` 404 | Wrong base URL | Verify production endpoint or set instance URL to dev |
| Empty results on every command | Company has no data yet, or API key scoped to wrong company | Check Darkmon tenant; rotate key |
| Feed fetch timing out | `Indicator fetch limit` too high | Lower to 500 or 200 |
| Passwords missing from table output | `redact_secrets` is on (the default) | Set to `false` only in dev contexts |

## Development

Source of truth is `Darkmon.py` (Python). The YAML's embedded `script:` block is
generated from it via `sync_yaml.py`. Tests live in `Darkmon_test.py`. Run:

```
python sync_yaml.py            # write Darkmon.py into Darkmon.yml's script block
python sync_yaml.py --check    # CI-friendly drift check
python -m pytest Darkmon_test.py
```

The pre-commit hook and CI workflow at the repo root run both automatically.

## Versioning

See [`../../ReleaseNotes/`](../../ReleaseNotes/).
