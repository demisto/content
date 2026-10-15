Test pack for demisto-sdk CIAC-18570. Do not merge.

- `TCTNoConnector`: no connector, sets `excludefromtightlycoupled: true` (CO192 should pass).
- `TCTWithConnector`: referenced by the `tightly-coupled-test` connector and sets `excludefromtightlycoupled: true` (CO196 should fail).
