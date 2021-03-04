Read QR Code from image file.
This integration was integrated and tested with version xx of QR Code Reader - goqr.me
## Configure QR Code Reader - goqr.me on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for QR Code Reader - goqr.me.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### read-qr-code-from-file
***
Upload a PNG, GIF or JP(E)G image which is smaller than 1 MiB via the entry_id of the image file.


#### Base Command

`read-qr-code-from-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of image file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRCode | unknown | QR Code data obtained | 


#### Command Example
``` ```

#### Human Readable Output


