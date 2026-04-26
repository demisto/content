# SOC Framework Pack Manager — Post-Install Steps

The pack is installed. Before running any commands, configure the integration instance.

---

## Required: Configure the Integration Instance

The `SOCFWPackManager` command installs packs by posting directly to the XSIAM content bundle endpoint. Credentials are stored in the integration instance — not passed as command arguments.

**Steps:**

1. Go to **Settings → Configurations → Integrations → API Keys**
2. Click **+ New Key** → select **Standard** → choose a role with content management permissions
3. Copy the generated **API Key**
4. Note your **Key ID** from the ID column
5. Click **Copy API URL** to get your Server URL
6. Go to **Settings → Integrations** → find **SOC Framework Pack Manager** → **Add Instance**
7. Enter:
   - **Server URL** — the URL from step 5
   - **API Key ID** — the ID from step 4
   - **API Key** — the key from step 3
8. Click **Test** to verify, then **Save**

---

## You're Ready

```
!SOCFWPackManager action=list
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
!SOCFWPackManager action=sync-tags
```

See [README_COMMANDS.md](README_COMMANDS.md) for the full command reference.
