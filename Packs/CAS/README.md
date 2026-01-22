# CAS Pack Guide & Contribution Example

## Contribution Flow - Overview

This pack serves as an example for contributors on how to interact with the Cortex APIs without modifying the Core integration directly.

### The Solution

1. **Generic API Command**: A new command `core-generic-api-call` has been implemented.
2. **Tenant-Specific Core**: An enhanced version of the Core integration (containing this command) is uploaded manually to the developer's tenant (it will not be merged to the main repository).
3. **Isolated Pack**: Contributors write their scripts and actions in a dedicated pack (like this CAS pack).
4. **Execution**: Instead of calling platform APIs directly, scripts in this pack use `demisto.executeCommand('core-generic-api-call', ...)` to perform API requests.

---

## How to Clone the Forked Repo

To clone the forked repository, use the following command:

```bash
git clone https://github.com/mayyagoldman/content.git
cd content
```

---

## How to use demisto-sdk upload (Cortex Platform)

### Overview

Upload a content entity to Cortex.

In order to run the command, `DEMISTO_BASE_URL` environment variable should contain the Cortex XSIAM instance URL, and `DEMISTO_API_KEY` environment variable should contain a valid Cortex XSIAM API Key.

### Notes for Cortex XSIAM

* **Cortex Base URL** should be retrieved from Settings -> Configurations -> API Keys -> Copy URL button in the top right corner.
* **API key** should be of a standard security level, and have the Instance Administrator role.
* To use the command the `XSIAM_AUTH_ID` environment variable **must** be set.

### Configuration

```bash
export DEMISTO_BASE_URL=<YOUR_BASE_URL>
export DEMISTO_API_KEY=<YOUR_API_KEY>
export XSIAM_AUTH_ID=<THE_XSIAM_AUTH_ID>
```

### Uploading the CAS Pack

```bash
demisto-sdk upload --marketplace platform -i Packs/CAS
```
