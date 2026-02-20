## Superna Zero Trust Integration

Integrates Cortex XSOAR with **Superna Zero Trust** to automate ransomware containment and recovery actions.

### Configure Superna Zero Trust on Cortex XSOAR

1. Go to **Settings → Integrations → Servers & Services**
2. Search for **Superna Zero Trust**
3. Click **Add instance**
4. Configure the following parameters:
   - **API URL**: Base URL of your Superna Zero Trust / SERA server (e.g. `https://172.31.1.102`)
   - **API Key**: API key stored securely using Cortex XSOAR credentials
   - **Trust any certificate**: Enable only if using self-signed certificates
   - **Use system proxy**: Optional

5. Click **Test** to validate connectivity

### Commands

| Command | Description |
|--------|-------------|
| `superna-zt-snapshot-critical-paths` | Snapshot Superna critical paths for ransomware recovery |
| `superna-zt-lockout-user` | Lock out a user from NAS storage access |
| `superna-zt-unlock-user` | Unlock a user from NAS storage access |

### Use Cases

- Ransomware containment
- Insider threat response
- Zero Trust enforcement
- NAS data protection

### Security Notes

- API keys are stored using Cortex XSOAR’s secure credentials store
- No secrets or IP addresses are embedded in playbooks
