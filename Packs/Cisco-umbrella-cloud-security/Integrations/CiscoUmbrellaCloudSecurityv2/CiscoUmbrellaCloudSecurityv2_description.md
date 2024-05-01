## Summary
Cisco Umbrella is a cloud security platform providing the first line of defense against internet threats.
It uses DNS-layer security to block malicious requests before a connection is established, offering protection against malware, ransomware, phishing, and more.
It offers real-time reporting, integrates with other Cisco solutions for layered security, and uses machine learning to uncover and predict threats.

## Configure Cisco Umbrella Cloud Security on Cortex XSOAR
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco Umbrella Cloud Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key | True |
    | API Secret | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the connection.