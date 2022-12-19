
**To get an API key on the GCenter:**

1. Log in to the GCenter home page https://10.10.10.10/ui/home/main.
2. Then, go to Admin/GCenter/Accounts.
3. Access to API Keys.
4. Add a new API Key with the `Operators` and/or the `Administrators` permissions.
5. Copy the API Key.

**Permissions required per command:**


| Commands                  | Permissions    |
|---------------------------| -------------- |
| gw-get-alert              | Operators      |
| gw-es-query               | Operators      |
| gw-es-wrapper             | Operators      |
| gw-file-infected          | Operators      |
| gw-add-malcore-list-entry | Administrators |
| gw-get-malcore-list-entry | Administrators |
| gw-del-malcore-list-entry | Administrators |
| gw-add-dga-list-entry     | Administrators |
| gw-get-dga-list-entry     | Administrators |
| gw-del-dga-list-entry     | Administrators |
| gw-get-ignore-asset-name  | Operators      |
| gw-get-ignore-kuser-ip    | Operators      |
| gw-get-ignore-kuser-name  | Operators      |
| gw-get-ignore-mac-address | Operators      |
| gw-add-ignore-asset-name  | Operators      |
| gw-add-ignore-kuser-ip    | Operators      |
| gw-add-ignore-kuser-name  | Operators      |
| gw-add-ignore-mac-address | Operators      |
| gw-del-ignore-asset-name  | Operators      |
| gw-del-ignore-kuser-ip    | Operators      |
| gw-del-ignore-kuser-name  | Operators      |
| gw-del-ignore-mac-address | Operators      |
| gw-send-malware           | Operators      |
| gw-send-powershell        | Operators      |
| gw-send-shellcode         | Operators      |
