## Summary

Cisco Umbrella is a cloud security platform providing the first line of defense against internet threats.
It uses DNS-layer security to block malicious requests before a connection is established, offering protection against malware, ransomware, phishing, and more.
It offers real-time reporting, integrates with other Cisco solutions for layered security, and uses machine learning to uncover and predict threats.

## How to get Cisco Umbrella Cloud Security v2 Credentials

Create an Umbrella API key and secret in the Umbrella admin console.

1. In Umbrella, navigate to **Admin** > **API Keys** (or **Settings** > **API Keys** in a Multi-org/MSP/MSSP management console) and click **Add** / **Create**.
2. Provide a name for the key (for example, `Cortex Cloud Security`) and select an expiration date.
3. Under **Key Scope**, expand **Policies** and grant the key the following scopes:
    - **Destination Lists** – Read / Write (Write is required for commands that add, update, or remove destinations/destination lists).
    - **Destinations** – Read / Write
4. Click **Create Key**.
5. Copy **Your Key (API Key)** and **Your Secret (API Secret)**, acknowledge the warning, and click **Close**.

> **Note:** A key with only **Read** permissions will allow `umbrella-destination-lists-list` / `umbrella-destinations-list` to succeed but write-style commands (e.g., `umbrella-destination-add`, `umbrella-destination-delete`, `umbrella-destination-list-create`, `umbrella-destination-list-delete`) will return `403 - Forbidden Access Forbidden`. Grant **Write** permissions on the Destination Lists scope to use those commands.

For the full list of Umbrella API OAuth scopes, see the official Cisco documentation: [Umbrella API OAuth scopes](https://developer.cisco.com/docs/cloud-security/umbrella-api-oauth-scopes/).

## Configure Cisco Umbrella Cloud Security v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco Umbrella Cloud Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key | True |
    | API Secret | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Base URL | True |

4. Click **Test** to validate the connection.
