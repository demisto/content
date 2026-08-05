## Spec Test Default

This is a **test integration** for validating that integrations without the `spec` field continue to work normally with the platform's default worker memory allocation (1 GB).

### About the `spec` Field

This integration intentionally does **not** include the `spec` field. It serves as a control/baseline to verify that the absence of the field is handled correctly by the SDK and platform.

### Configuration

1. **Server URL** — The base URL of the API endpoint.
2. **API Key** — Authentication key for the API.
