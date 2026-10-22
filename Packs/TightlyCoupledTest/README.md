Test pack for demisto-sdk CIAC-18570. Do not merge.

| Integration | Connector | `excludefromtightlycoupled` | Expected |
|---|---|---|---|
| `TCTNoConnector` | none | not set | CO192 fails |
| `TCTExcludedNoConnector` | none | `true` | CO192 passes |
| `TCTWithConnector` | `tightly-coupled-test` | `true` | CO196 fails |
| `TCTCoveredNoFlag` | `tightly-coupled-test-pass` | not set | CO196 passes |
