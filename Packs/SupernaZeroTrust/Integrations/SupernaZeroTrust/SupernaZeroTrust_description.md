## Superna Zero Trust

Integrates Cortex XSOAR with **Superna Zero Trust** to automate ransomware containment and recovery actions via the Superna SERA API.

### Prerequisites

- A running Superna Zero Trust / SERA server reachable from your XSOAR instance
- An API key with sufficient privileges to trigger lockout, unlock, and snapshot operations

### Get Your API Key

1. Log in to the Superna Zero Trust management interface
2. Navigate to **Settings → API Keys**
3. Generate or copy an existing API key

### Connection Parameters

| Parameter | Description |
|-----------|-------------|
| API URL | Base URL of your Superna SERA server (e.g. `https://sera.example.local`) |
| API Key | API key for authentication — stored securely in XSOAR credentials |
| Trust any certificate | Enable only for self-signed/internal certificates |
| Use system proxy | Enable if your XSOAR instance requires a proxy to reach the Superna server |
