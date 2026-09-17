# IBM Secrets Manager

IBM Secrets Manager is a centralized service to store, manage, and automate the lifecycle of secrets (API keys, passwords, TLS certificates, and arbitrary data), powered by HashiCorp Vault.

## What does this pack do?

- Collects IBM Secrets Manager audit / Activity Tracker events (via IBM Cloud Logs) into Cortex XSIAM.

The pack contains the **IBM Secrets Manager** integration, which authenticates to IBM Cloud using an IAM API key and queries the IBM Cloud Logs query API to fetch Secrets Manager audit events.
