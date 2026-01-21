# CAS Pack Guide & Contribution Example (Cortex XSIAM)

## Contribution Flow Overview (XSIAM Only)

This pack serves as an example for contributors on how to interact with the Cortex XSIAM platform APIs without modifying the Core integration directly.

### The Problem
Contributors often need to call internal XSIAM platform APIs. However, we want to avoid direct contributions to the Core integration to maintain stability and security.

### The Solution
1.  **Generic API Command**: A new command `core-generic-api-call` has been implemented.
2.  **Tenant-Specific Core**: An enhanced version of the Core integration (containing this command) is uploaded manually to the developer's XSIAM tenant (it will not be merged to the main repository).
3.  **Isolated Pack**: Contributors write their scripts and actions in a dedicated pack (like this CAS pack).
4.  **Execution**: Instead of calling platform APIs directly, scripts in this pack use `demisto.executeCommand('core-generic-api-call', ...)` to perform API requests. This ensures the calls run within the context of the single XSIAM tenant.

---

## How to Clone the Forked Repo

To clone the forked repository, use the following command:

```bash
git clone https://github.com/mayyagoldman/content.git
cd content
```

---

## How to use demisto-sdk upload (Cortex XSIAM)

### Overview
Upload a content entity to Cortex XSIAM.

In order to run the command, `DEMISTO_BASE_URL` environment variable should contain the Cortex XSIAM instance URL, and `DEMISTO_API_KEY` environment variable should contain a valid Cortex XSIAM API Key.

### Notes for Cortex XSIAM:
*   **Cortex XSIAM Base URL** should be retrieved from Settings -> Configurations -> API Keys -> Copy URL button in the top right corner.
*   **API key** should be of a standard security level, and have the Instance Administrator role.
*   To use the command the `XSIAM_AUTH_ID` environment variable **must** be set.

### Configuration
```bash
export DEMISTO_BASE_URL=<YOUR_XSIAM_BASE_URL>
export DEMISTO_API_KEY=<YOUR_XSIAM_API_KEY>
export XSIAM_AUTH_ID=<THE_XSIAM_AUTH_ID>
```

### Uploading the CAS Pack
```bash
demisto-sdk upload -i Packs/CAS
```

