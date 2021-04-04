Read QR Code from image file.
This integration was integrated and tested with version 1.0.0 of QR Code Reader - goqr.me
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
### goqr-read-qr-code-from-file
***
Upload a PNG, GIF or JP(E)G image which is smaller than 1 MiB via the entry_id of the image file.

#### Base Command

`goqr-read-qr-code-from-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of image file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoQRCodeData.data | unknown | QR Code data obtained | 
| GoQRCodeData.error | unknown | Errors reading QR code | 
| GoQRCodeData.seq | unknown | sequence numbers read from code | 


#### Command Example
``` ```

#### Human Readable Output

