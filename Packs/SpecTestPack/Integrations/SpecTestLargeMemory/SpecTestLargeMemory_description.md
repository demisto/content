## Spec Test Large Memory

This is a **test integration** for validating the new `spec` field on Integration content items.

### About the `spec` Field

The `spec` field determines the memory allocation size for the dedicated worker running this integration. This integration has `spec: L` (large) configured, indicating it requires extra memory for heavy data processing operations.

**Possible `spec` values:**
- `S` — Small memory allocation
- `M` — Medium memory allocation
- `L` — Large memory allocation

### Configuration

1. **Server URL** — The base URL of the API endpoint.
2. **API Key** — Authentication key for the API.
