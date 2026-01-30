# XSOAR Upload Troubleshooting Guide

## The Problem

When trying to upload without Auth ID, you get:

```
ERROR:
Could not parse server version, please make sure the environment is properly configured.
Could not connect to the server. Try checking your connection configurations.
```

## Why This Happens

```
┌─────────────────────────────────────────────────────────────┐
│  XSOAR 8.x Cloud Authentication Requirements                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ✅ API URL:     https://api-superna.crtx...                │
│  ✅ API Key:     9UBIRKC...ofwV                             │
│  ❌ Auth ID:     ??? (MISSING)                              │
│                                                              │
│  Without all 3, authentication FAILS                        │
└─────────────────────────────────────────────────────────────┘
```

## How to Find Your Auth ID

### Visual Guide

```
Step 1: Log into XSOAR
┌─────────────────────────────────────────────────────────────┐
│ 🌐 https://superna.crtx.ca.paloaltonetworks.com            │
└─────────────────────────────────────────────────────────────┘

Step 2: Navigate to Settings
┌─────────────────────────────────────────────────────────────┐
│  [Top Right Corner]                                          │
│  ⚙️  Settings → Configurations → API Keys                   │
└─────────────────────────────────────────────────────────────┘

Step 3: Look for API Keys Table
┌─────────────────────────────────────────────────────────────┐
│  API Keys                                        [+ Get Key] │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Name      │ Key          │ Auth ID │ Role           │   │
│  ├───────────┼──────────────┼─────────┼────────────────┤   │
│  │ My Key    │ 9UBIRKC...   │  12345  │ Administrator  │   │
│  └───────────┴──────────────┴─────────┴────────────────┘   │
│                                   ↑                          │
│                            THIS NUMBER!                      │
└─────────────────────────────────────────────────────────────┘
```

### What You're Looking For

```
✅ CORRECT - Auth ID Examples:
   - 1
   - 123
   - 12345
   - 987654321

❌ WRONG - These are NOT Auth IDs:
   - 9UBIRKcQRRZptxj... (This is the API Key)
   - https://api-superna... (This is the URL)
   - superna (This is your instance name)
```

## Once You Have the Auth ID

### Option 1: Use the Helper Script

```bash
cd /Users/andrew/Documents/integrations/XSOAR/content/Packs/SupernaZeroTrust
./upload-to-xsoar.sh <YOUR_AUTH_ID>
```

Example:
```bash
./upload-to-xsoar.sh 12345
```

### Option 2: Run Commands Manually

```bash
# Set all three required variables
export DEMISTO_BASE_URL=https://api-superna.crtx.ca.paloaltonetworks.com
export DEMISTO_API_KEY=9UBIRKcQRRZptxj12ZSBGwl4BtOyIF7hKXbKN5AlPhmluL6Ton6U8Rs7EdBDqAGyfJNxvgeYkq67JymGPBK5MZyfsbaE86LAcLBDwRVBCR5NWbeA2D4WjqxCqcDzofwV
export XSIAM_AUTH_ID=12345  # ← Replace with your actual Auth ID

# Navigate to content directory
cd /Users/andrew/Documents/integrations/XSOAR/content

# Upload the pack
demisto-sdk upload -i Packs/SupernaZeroTrust -z --override-existing
```

## Success! What You'll See

When it works, you'll see:

```
✅ Uploading pack SupernaZeroTrust...
✅ Pack uploaded successfully
✅ Pack installed: SupernaZeroTrust
```

## Still Having Issues?

### Check 1: Verify Auth ID Format
```bash
echo $XSIAM_AUTH_ID
# Should output a number like: 12345
# NOT empty, NOT "undefined", NOT the API key
```

### Check 2: Test Connection
```bash
# Test if variables are set correctly
echo "URL: $DEMISTO_BASE_URL"
echo "Auth ID: $XSIAM_AUTH_ID"
echo "API Key length: ${#DEMISTO_API_KEY}"
```

### Check 3: Try with Verbose Output
```bash
demisto-sdk upload -i Packs/SupernaZeroTrust -z --override-existing \
  --console-log-threshold DEBUG
```

## Alternative: Skip SDK Upload Entirely

If you still can't get the Auth ID or SDK upload working:

### Manual Upload via XSOAR UI (5 minutes)

```
┌─────────────────────────────────────────────────────────────┐
│  1. Integration Upload                                       │
│  ────────────────────────────────────────────────────────   │
│  Settings → Objects Setup → Integrations                    │
│  → "New Integration" → Paste code → Save                    │
│                                                              │
│  2. Playbook Upload                                          │
│  ────────────────────────────────────────────────────────   │
│  Incidents → Playbooks → "New" → Import                     │
│  → Upload each YAML file                                    │
│                                                              │
│  ✅ No Auth ID needed!                                      │
│  ✅ Works immediately!                                      │
└─────────────────────────────────────────────────────────────┘
```

### Files to Upload Manually:

**Integration:**
- `Packs/SupernaZeroTrust/Integrations/SupernaZeroTrust/SupernaZeroTrust.yml`
- `Packs/SupernaZeroTrust/Integrations/SupernaZeroTrust/SupernaZeroTrust.py`

**Playbooks:**
- `Packs/SupernaZeroTrust/Playbooks/Superna_Zero_Trust_Snapshot.yml`
- `Packs/SupernaZeroTrust/Playbooks/Superna_Zero_Trust_User_Lockout.yml`
- `Packs/SupernaZeroTrust/Playbooks/Superna_Zero_Trust_Request_User_Storage_Lockout.yml`
- `Packs/SupernaZeroTrust/Playbooks/Superna_Zero_Trust_Request_User_Storage_UnLockout.yml`

## Need More Help?

Contact me with:
1. Screenshot of Settings → API Keys page (hide sensitive data)
2. Output of: `demisto-sdk --version`
3. What XSOAR version you see at bottom of XSOAR page
