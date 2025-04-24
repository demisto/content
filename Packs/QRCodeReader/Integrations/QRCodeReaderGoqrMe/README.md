Read QR Code from image file.
This integration was integrated and tested with version 1.0.0 of QR Code Reader - goqr.me
## Configure QR Code Reader - goqr.me in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
