# XSOAR 8.x Cloud SDK Upload Requirements

Based on official Palo Alto Networks documentation:
- [demisto-sdk upload README](https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/upload/README.md)
- [Cortex XSOAR API Keys Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-8/cortex-xsoar-admin/cortex-xsoar-overview/cortex-xsoar-api-keys)
- [XSOAR Troubleshooting Guide](https://live.paloaltonetworks.com/t5/cortex-xsoar-discussions/xsoar-xdr-public-api-unauthorised/td-p/480153)

## Current Issue: 401 Unauthorized

Your XSOAR 8.x cloud instance (`api-superna.crtx.ca.paloaltonetworks.com`) is rejecting API calls with:
```
{"reply": {"err_code": 401, "err_msg": "Public API request unauthorized", "err_extra": null}}
```

## Official Requirements for XSOAR 8.x Cloud

### 1. API Key Configuration

**CRITICAL**: For XSOAR 8.x (XSIAM mode), the API key MUST have:

✅ **Role**: `Instance Administrator`
✅ **Security Level**: `Standard` (NOT Advanced)

**Current Status**: Unknown - Need to verify in Settings → API Keys

### 2. Environment Variables

```bash
export DEMISTO_BASE_URL="https://api-superna.crtx.ca.paloaltonetworks.com"
export DEMISTO_API_KEY="<YOUR_API_KEY>"
export XSIAM_AUTH_ID="<YOUR_AUTH_ID>"
```

**Note**: The Base URL should be copied from Settings → Configurations → API Keys → Copy URL button (NOT from browser address bar)

### 3. Upload Command

```bash
demisto-sdk upload -i Packs/SupernaZeroTrust -z --xsiam --insecure --skip_validation
```

Flags explained:
- `-z` - Compress pack to zip (REQUIRED for XSOAR 8.x)
- `--xsiam` - Use XSIAM/XSOAR 8.x mode (REQUIRED)
- `--insecure` - Skip SSL verification
- `--skip_validation` - Skip pack validation (for custom content)

## Troubleshooting Steps

### Step 1: Verify API Key Permissions

1. Log into XSOAR at `https://superna.crtx.ca.paloaltonetworks.com`
2. Go to **Settings → Integrations → API Keys**
3. Find your API key (ID: 1 or 2)
4. Check the **Role** column - it MUST show **"Instance Administrator"**
5. Check **Security Level** - it MUST show **"Standard"**

**If the role is NOT Instance Administrator:**
- Click the API key
- Change Role to "Instance Administrator"
- Regenerate the key
- Update your `DEMISTO_API_KEY` environment variable

### Step 2: Verify URL Configuration

The official documentation states that for XSIAM/XSOAR 8.x:
- Base URL should come from Settings → Configurations → API Keys → **Copy URL** button
- NOT from the browser URL

**Action Required:**
1. In XSOAR, go to Settings → Configurations → API Keys
2. Click the **"Copy URL"** button (top right)
3. Verify it matches: `https://api-superna.crtx.ca.paloaltonetworks.com`

### Step 3: Check Time Synchronization

According to the [XSOAR troubleshooting forum](https://live.paloaltonetworks.com/t5/cortex-xsoar-discussions/xsoar-xdr-public-api-unauthorised/td-p/480153):

> "The issue was directly resolved by ensuring that the Time on the XSOAR was up to date and synchronised."

**This is managed by Palo Alto Networks for cloud instances** - you cannot fix this yourself. If this is the issue, contact support.

### Step 4: Multi-Tenant Configuration

If this is a multi-tenant XSOAR instance, the [CI/CD documentation](https://xsoar.pan.dev/docs/reference/packs/content-management) states:

> "You cannot run the playbook on the Main account on Multi-Tenant deployments."

**Check if this applies:**
- Are you using a Main/Parent account in a multi-tenant setup?
- If yes, you need to use a tenant account instead

## Alternative: Manual Pack Installation

If SDK upload continues to fail due to API restrictions, use the **CustomPackInstaller** method:

1. Create a test incident in XSOAR
2. Go to the War Room tab
3. Upload `SupernaZeroTrust.zip` as an attachment
4. Note the entry ID (e.g., `123@456`)
5. Run: `!CustomPackInstaller entry_id="123@456" skip_verify=true`

This bypasses API authentication and signature requirements.

## Next Steps

1. **Verify API key has Instance Administrator role**
2. **Verify you're using the correct Base URL from "Copy URL" button**
3. **Try upload again with corrected configuration**
4. **If still failing, contact Palo Alto Networks support** with this information:
   - Error: 401 Unauthorized on `/public_api/v1/system/info`
   - Instance: api-superna.crtx.ca.paloaltonetworks.com
   - SDK version: 1.38.18
   - Auth ID: 1 or 2
   - Request: Enable API access for custom pack uploads

## Working Configuration Example

Once you have Instance Administrator API key:

```bash
#!/bin/bash
export DEMISTO_BASE_URL="https://api-superna.crtx.ca.paloaltonetworks.com"
export DEMISTO_API_KEY="<INSTANCE_ADMIN_KEY>"
export XSIAM_AUTH_ID="<AUTH_ID>"

demisto-sdk upload \
  -i Packs/SupernaZeroTrust \
  -z \
  --xsiam \
  --insecure \
  --skip_validation \
  --console-log-threshold DEBUG
```

## References

- [demisto-sdk Upload Command](https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/upload/README.md)
- [XSOAR API Keys Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-8/cortex-xsoar-admin/cortex-xsoar-overview/cortex-xsoar-api-keys)
- [XSOAR CI/CD Guide](https://xsoar.pan.dev/docs/reference/packs/content-management)
- [401 Unauthorized Troubleshooting](https://live.paloaltonetworks.com/t5/cortex-xsoar-discussions/xsoar-xdr-public-api-unauthorised/td-p/480153)
