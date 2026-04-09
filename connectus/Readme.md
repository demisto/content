Note, this folder should not be merged to master.
## Authentication Type Catalog

Each integration's authentication parameters are classified into one of the
following auth type enums.  The CSV columns use these enum values.

| Auth Type Enum | Description |
|---|---|
| `API_KEY` | API Key authentication — a single secret key/token |
| `CREDENTIALS` | Username/Password credentials pair (XSOAR type 9 widget) |
| `OAUTH_CLIENT_CREDENTIALS` | OAuth 2.0 Client Credentials flow (client_id + client_secret) |
| `OAUTH_AUTH_CODE` | OAuth 2.0 Authorization Code flow (client_id + client_secret + auth_code/redirect_uri) |
| `OAUTH_DEVICE_CODE` | OAuth 2.0 Device Code flow |
| `BEARER_TOKEN` | Bearer token / API token authentication |
| `CERTIFICATE` | Certificate-based authentication (certificate + private_key) |
| `BASIC_AUTH` | Basic authentication (username + password, not using type 9 widget) |
| `AWS_AUTH` | AWS-style authentication (access_key + secret_key + optional role/session) |
| `CUSTOM_CREDENTIALS` | Custom credentials (type 12 widget) |
| `MANAGED_IDENTITY` | Azure Managed Identity authentication |
| `NONE` | No authentication required |

### How to Read the CSV Columns

| Column | Description |
|---|---|
| **Integration Name** | Display name of the integration |
| **Support Level** | `xsoar`, `partner`, or `community` |
| **Provider** | The vendor / author of the pack |
| **Auth Types** | Pipe-separated list of auth type enums, e.g. `CREDENTIALS \| API_KEY` |
| **Auth Requirement** | Shows which auth types are required vs. optional. Examples: `REQUIRED(CREDENTIALS)`, `CHOICE(API_KEY, OAUTH_CLIENT_CREDENTIALS)`, `REQUIRED(CREDENTIALS) + OPTIONAL(CERTIFICATE)` |
| **Auth Params** | Semicolon-separated list of individual parameters, each tagged: `param_name[AUTH_TYPE](typeN,required/optional)` |

#### Requirement Semantics

- **REQUIRED(X)** — Auth type X must be configured.
- **OPTIONAL(X)** — Auth type X can optionally be configured.
- **CHOICE(X, Y)** — The integration has an auth-type selector; the user picks one of X or Y.
- **REQUIRED(X) + OPTIONAL(Y)** — X is mandatory, Y is an additional optional method.
