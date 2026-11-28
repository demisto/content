## Zero Networks Segment Assets

This integration looks up an asset in Zero Networks Segment by its fully qualified domain name and then quarantines or releases it. The main use case is containment: when an alert names a host, a playbook can resolve that host to a Zero Networks asset and block its network traffic without an analyst leaving Cortex, then restore it once the incident is closed.

To interact with the Zero Networks API, you need to generate an API key. Follow the steps below to create and configure your API token.

### Generate an API Key

#### 1. **Log in to the Zero Networks Portal**

1. Go to [portal.zeronetworks.com](https://portal.zeronetworks.com).
2. Log in using your email address.
3. Authenticate using the code sent to your email.

#### 2. **Navigate to API Key Settings**

1. Go to **Settings** > **System** > **Integrations** > **API**.
2. Click on **Add new token**.

#### 3. **Fill in the Required Fields**

- **Token Name:** Provide a name for your token.

- **Access Type:** The token must allow write access. A read-only token can perform only GET API requests, which is enough for `zero-networks-segment-asset-search` but not for the quarantine commands.

- **Expiry:** Set the token expiration period (1-36 months).

#### 4. **Create and Copy the Token**

1. Click **Add** to create the token.
2. Copy the token immediately. **Note:** The token will not be displayed again after this step. If needed, the token can be regenerated at any time.

### Troubleshooting

- **Authorization Error on Test:** The API key is wrong or has expired. Tokens expire after the period set when they were created, so regenerate the token in the portal and update the instance.
- **The quarantine commands fail but the search command works:** The token was created as read only. Read-only tokens can issue only GET requests. Create a token with write access.
- **No asset was found for the FQDN:** The FQDN must match the value Zero Networks holds for the asset, which is the fully qualified name (for example `server.domain.local`) rather than the short host name. Search for the asset in the portal to confirm the exact value.
