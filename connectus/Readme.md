Note, this folder should not be merged to master.
## Authentication Type Catalog

Each integration's authentication parameters are classified by the **actual
HTTP authentication mechanism** used, not by the XSOAR widget type.  Each auth
type is also tagged as **STATIC** or **DYNAMIC** based on its credential
lifecycle.

### Static vs Dynamic Credentials

| Lifecycle | Meaning |
|---|---|
| **STATIC** | The credentials themselves are sent directly with each request (API key in header, basic auth, bearer token). They don't change or expire (or expire very slowly). |
| **DYNAMIC** | The credentials are used to *obtain* a temporary access token from an auth endpoint. The actual API calls use the temporary token. Examples: OAuth flows, managed identity, any integration that calls a `/token` or `/auth` endpoint first. |

### Auth Type Enum Reference

| Auth Type Enum | Lifecycle | Description |
|---|---|---|
| `BASIC_AUTH` | STATIC | Basic Authentication — username:password sent as Base64 in Authorization header (or used directly in request body). STATIC. |
| `BEARER_TOKEN` | STATIC | Bearer Token — a token/key sent in Authorization: Bearer header or as a query/header param. STATIC. |
| `API_KEY` | STATIC | API Key — a key sent as a header (e.g., x-api-key), query parameter, or in request body. STATIC. |
| `OAUTH_CLIENT_CREDENTIALS` | DYNAMIC | OAuth 2.0 Client Credentials — client_id + client_secret exchanged for an access token via token endpoint. DYNAMIC. |
| `OAUTH_AUTH_CODE` | DYNAMIC | OAuth 2.0 Authorization Code — involves redirect_uri, auth_code, client_id, client_secret. DYNAMIC. |
| `OAUTH_DEVICE_CODE` | DYNAMIC | OAuth 2.0 Device Code flow. DYNAMIC. |
| `CERTIFICATE` | STATIC | Certificate/mTLS — client certificate + private key for mutual TLS. STATIC. |
| `AWS_SIGNATURE` | STATIC | AWS Signature V4 — access_key + secret_key used to sign requests. STATIC. |
| `MANAGED_IDENTITY` | DYNAMIC | Azure/GCP Managed Identity — no user credentials, identity from cloud platform. DYNAMIC. |
| `HMAC` | STATIC | HMAC-based signing — a secret key used to compute HMAC signatures on requests. STATIC. |
| `NONE` | STATIC | No authentication required. |

### How to Read the CSV Columns

| Column | Description |
|---|---|
| **Integration Name** | Display name of the integration |
| **Support Level** | `xsoar`, `partner`, or `community` |
| **Provider** | The vendor / author of the pack |
| **Auth Types** | Pipe-separated list of auth type enums, e.g. `BASIC_AUTH \| OAUTH_CLIENT_CREDENTIALS` |
| **Auth Credential Lifecycle** | `STATIC`, `DYNAMIC`, or `STATIC + DYNAMIC` (if multiple auth types with different lifecycles) |
| **Auth Requirement** | Shows which auth types are required vs. optional. Examples: `REQUIRED(BASIC_AUTH)`, `CHOICE(API_KEY, OAUTH_CLIENT_CREDENTIALS)`, `REQUIRED(BASIC_AUTH) + OPTIONAL(CERTIFICATE)` |
| **Auth Params** | Semicolon-separated list of individual parameters, each tagged: `param_name[AUTH_TYPE](typeN,required/optional)` |

#### Requirement Semantics

- **REQUIRED(X)** — Auth type X must be configured.
- **OPTIONAL(X)** — Auth type X can optionally be configured.
- **CHOICE(X, Y)** — The integration has an auth-type selector; the user picks one of X or Y.
- **REQUIRED(X) + OPTIONAL(Y)** — X is mandatory, Y is an additional optional method.
