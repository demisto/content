Use the S/MIME (Secure Multipurpose Internet Mail Extensions) integration to send and receive secure MIME data.
This integration was integrated and tested with version 0.40.1 of M2Crypto.

## Use Cases

- Send an S/MIME-signed message.
- Send an S/MIME-encrypted message.
- Send an S/MIME-signed and encrypted message.
- Decrypt an S/MIME message.

## Usage

- In order to send signed/encrypted messages using the S/MIME Messaging and Mail Sender (New) perform the following steps:

    1. Run the `smime-sign-and-encrypt` command with the required parameters.
    2. Enter the output message from step 1 as the input for the `raw_message` argument of the `send-mail` command in the Mail Sender (New) integration (e.g., the value stored in the Context Data under `SMIME.SignedAndEncrypted.Message`).
    3. Run the `send-mail` command with the `raw_message` argument (as described in step 2), with any of the optional arguments `to`, `cc` and `bcc` (e.g., `!send-mail to=user@email.com raw_message=${SMIME.SignedAndEncrypted.Message}`).

- While decrypting or verifying a message, S/MIME Messaging will attempt to parse the message into readable text, as well as extract any attachments and images if present. If you wish to get the raw message instead, use the raw_output argument.

## Configure SMIME Messaging in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Public Key | Sender public key required for signing emails. | True |
| Private Key | Sender private key required for decrypting and signing emails. | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### smime-verify-sign

***
Verifies the signature.

Warning: This function does not check the CA chain. Ensure the certificate chain is validated separately to avoid security risks.

#### Base Command

`smime-verify-sign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| signed_message | Entity ID of the file with a .p7 extension containing the signed message. | Required | 
| public_key | Sender's public key to verify. Default is instancePublicKey. | Optional | 
| raw_output | Whether to get the full raw output of the email. Possible values are: false, true. | Optional | 
| tag | A comma-separated list of tags to be included in the War Room output. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SMIME.Verified.Message | String | The decoded signed message. | 

#### Command example

```!smime-verify-sign signed_message=454@6cc2adad-6d3b-4fec-8b98-99b1b1770bc5```

#### Context Example

```json
{
    "SMIME": {
        "Verified": {
            "Message": "This is a message to sign"
        }
    }
}
```

#### Human Readable Output

>### The signature verified, message is: 
>
>***
> This is a message to sign

### smime-decrypt-email-body

***
Decrypts the message body.

#### Base Command

`smime-decrypt-email-body`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| encrypt_message | Entity ID of the file with a .p7 extension containing the encrypted email. | Required | 
| encoding | The encoding code to use when decoding the message body, e.g., 'ISO-8859-2''. | Optional | 
| raw_output | Whether to get the full raw output of the email. Possible values are: false, true. | Optional | 
| tag | A comma-separated list of tags to be included in the War Room output. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SMIME.Decrypted.Message | String | The decrypted message. | 

#### Command example

```!smime-decrypt-email-body encrypt_message=451@6cc2adad-6d3b-4fec-8b98-99b1b1770bc5```

#### Context Example

```json
{
    "SMIME": {
        "Decrypted": {
            "Message": "This is a message to encrypt"
        }
    }
}
```

#### Human Readable Output

>### The decrypted message is: 
>
>***
> This is a message to encrypt

### smime-sign-and-encrypt

***
Encrypts and signs an email message with S/MIME protocol by using a public RSA certificate.

#### Base Command

`smime-sign-and-encrypt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message body to encrypt and sign. | Required | 
| recipients | JSON dict of recipients and their public keys<br/>Format: {"recipient@email":"cert", "other@email":"cert"}<br/>Use "instancePublicKey" in the cert field to use the instance certificate. | Optional | 
| cc | JSON dict of cc recipients and their public keys<br/>Format: {"cc@email":"cert", "othercc@email":"cert"}<br/>Use "instancePublicKey" in the cert field to use the instance certificate. | Optional | 
| bcc | JSON dict of bcc recipients and their public keys<br/>Format: {"bcc@email":"cert", "otherbcc@email":"cert"}<br/>Use "instancePublicKey" in the cert field to use the instance certificate. | Optional | 
| attachment_entry_id | List of War Room entry IDs of files to attach to the mail. | Optional | 
| signed | Whether the mail should be signed. Possible values are: true, false. Default is true. | Optional | 
| encrypted | Whether the mail should be encrypted. Possible values are: true, false. Default is true. | Optional | 
| sender | Sender email address. | Optional | 
| subject | Email subject. | Optional | 
| create_file_p7 | Whether to create a file with the encrypted/signed content. Possible values are: false, true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SMIME.SignedAndEncrypted.Message | String | The raw message to send. | 
| SMIME.SignedAndEncrypted.RecipientIds | String | Address of the recipient. | 
| SMIME.SignedAndEncrypted.FileName | String | Name of the file output if create_file_p7 is used. | 

#### Command example

```!smime-sign-and-encrypt message="This is a message to sign" encrypted=false```

#### Context Example

```json
{
    "SMIME": {
        "SignedAndEncrypted": {
            "FileName": "",
            "Message": "Date: Mon, 05 Aug 2024 08:56:00 +0000\r\nMIME-Version: 1.0\nContent-Disposition: attachment; filename=\"smime.p7m\"\nContent-Type: application/x-pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"\nContent-Transfer-Encoding: base64\n\nMIIJ4gYJKoZIhvcNAQcCoIIJ0zCCCc8CAQExDzANBglghkgBZQMEAgEFADCCAUkG\nCSqGSIb3DQEHAaCCAToEggE2Q29udGVudC1UeXBlOiBtdWx0aXBhcnQvbWl4ZWQ7\nIGJvdW5kYXJ5PSI9PT09PT09PT09PT09PT0wNTEzMzU2NzMxMDg3NTk4NjkxPT0i\nDQpNSU1FLVZlcnNpb246IDEuMA0KDQotLT09PT09PT09PT09PT09PTA1MTMzNTY3\nMzEwODc1OTg2OTE9PQ0KQ29udGVudC1UeXBlOiB0ZXh0L3BsYWluOyBjaGFyc2V0\nPSJ1cy1hc2NpaSINCk1JTUUtVmVyc2lvbjogMS4wDQpDb250ZW50LVRyYW5zZmVy\nLUVuY29kaW5nOiA3Yml0DQoNClRoaXMgaXMgYSBtZXNzYWdlIHRvIHNpZ24NCi0t\nPT09PT09PT09PT09PT09MDUxMzM1NjczMTA4NzU5ODY5MT09LS0NCqCCBb0wggW5\nMIIDoaADAgECAhAWjRiNCtW2fdBrguq+Q6aTMA0GCSqGSIb3DQEBCwUAMIGBMQsw\nCQYDVQQGEwJJVDEQMA4GA1UECAwHQmVyZ2FtbzEZMBcGA1UEBwwQUG9udGUgU2Fu\nIFBpZXRybzEXMBUGA1UECgwOQWN0YWxpcyBTLnAuQS4xLDAqBgNVBAMMI0FjdGFs\naXMgQ2xpZW50IEF1dGhlbnRpY2F0aW9uIENBIEczMB4XDTI0MDcyMTA4MzkwMFoX\nDTI1MDcyMTA4MzkwMFowJDEiMCAGA1UEAwwZc20uc21pbWUudGVzdGVyQGdtYWls\nLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcJHez4H953XJAG\nSRzfh+/HtTvqC0cu+KEeiGK/WYXuYZtjNb3Z7P++/DCZkWZ6FAMKZyMJqEwNiYsd\ndvirSdOHpfgPSKtTILiFXtTogGjPydAZvxri9x8Kg1AnyKwk4WJi3ftfgaIFpo8i\nF7BKS36IDpdb3O43mlLwXfOdWQBPlY0ndYPIWS+elbSHbHH+s8ai6CGcFoB3Akyb\nvIbSjVj5YFKky0wYVeXtJpgYlZoOFUmkCI5jpSTlCFIUm2bwIFwCeXt/hl0xHaXM\nfCPpX7B+EYLd2wUei2ZeEaDMi5Gnd9ANBlP9c8xe+KXQQ3vy1OT1ptd0YscOMz6E\nyhZLut0CAwEAAaOCAYcwggGDMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUvpep\nqoS/gL8QU30JMvnhLjIbz3cwfgYIKwYBBQUHAQEEcjBwMDsGCCsGAQUFBzAChi9o\ndHRwOi8vY2FjZXJ0LmFjdGFsaXMuaXQvY2VydHMvYWN0YWxpcy1hdXRjbGlnMzAx\nBggrBgEFBQcwAYYlaHR0cDovL29jc3AwOS5hY3RhbGlzLml0L1ZBL0FVVEhDTC1H\nMzAkBgNVHREEHTAbgRlzbS5zbWltZS50ZXN0ZXJAZ21haWwuY29tMBQGA1UdIAQN\nMAswCQYHZ4EMAQUBATAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwSAYD\nVR0fBEEwPzA9oDugOYY3aHR0cDovL2NybDA5LmFjdGFsaXMuaXQvUmVwb3NpdG9y\neS9BVVRIQ0wtRzMvZ2V0TGFzdENSTDAdBgNVHQ4EFgQUq8xlmZF/uLyAf3JUU1Bc\nXr+QRKMwDgYDVR0PAQH/BAQDAgWgMA0GCSqGSIb3DQEBCwUAA4ICAQCwNi6XtZwt\ne/mwEAswIi9OSHLAT7ruUNksl+RP8LdZQ9gyVxv5kER5mfdOF5ATO2OQ7Z/Y+ahs\n2Fk69tNckmq6tf4yhBGlWsHyYOLo+Njg0UVxah0NtDrbZfwqY6PeE5rcH7evYbpn\nfP25wf/5hZlqokpe+WwBTpxJLC6uRVQIdMpUKjRhpGJlRMUy7VZhzKzTqlkwAFID\nCaYAItFJ8DsVroZxq2A7g+jlrwc5tAaYglydn96HD4DOKmLPtHN3HkUrKuoXYDiN\n/ccZZ8wYRBB3zP1FjNyK8FHhjJpn70DY6sOvPn3ShzSL4vPEKYG1qABwTdToRh8v\ndZ4FlM4apSSRhZyaKGvfRzT1XlAE1zRlUWd2krNV+WXrLrs6NF0RKRtSR+IP5QmH\nKhgZJeUv2cgiOD+7Gx+7QTi0rERj9nH+jvvX1dn8kncT/PYuLBkHg1c1Xyv1o5vW\nNHfiIsqZMVUW+aZPm92k77+/AcgOaHcvqTP8vxbZBOgf959VSLma/n7NDprhjNg6\nO7pHh/cAB35gu9Q7acZE9NEwc+J0vl4LVx7YlP0aEaR8BOaFufQyOwD+2JV2f0bQ\nXwltX2Gr77xsOZKI/2pVn9Oj6xyW3h7ZrlA7Me/l4H9VAHoi6epON8r9wI+UDJKo\nIz3nxuKNFYDgnjtIaYrX5xjprYVX3fJlAzGCAqkwggKlAgEBMIGWMIGBMQswCQYD\nVQQGEwJJVDEQMA4GA1UECAwHQmVyZ2FtbzEZMBcGA1UEBwwQUG9udGUgU2FuIFBp\nZXRybzEXMBUGA1UECgwOQWN0YWxpcyBTLnAuQS4xLDAqBgNVBAMMI0FjdGFsaXMg\nQ2xpZW50IEF1dGhlbnRpY2F0aW9uIENBIEczAhAWjRiNCtW2fdBrguq+Q6aTMA0G\nCWCGSAFlAwQCAQUAoIHkMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI\nhvcNAQkFMQ8XDTI0MDgwNTA4NTYwMFowLwYJKoZIhvcNAQkEMSIEIJxfZpuZLFhT\n/xN2gZGCKzEPOnGX6uuyA5byB32PPlsqMHkGCSqGSIb3DQEJDzFsMGowCwYJYIZI\nAWUDBAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYI\nKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMCAgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMC\nAgEoMA0GCSqGSIb3DQEBAQUABIIBAFZZ5ExsKfb+hCgY5YQcVodYC74CmcCaN6fc\nJG6jL0yDNUV7wzuUNMT/DoxhKFI/2MNNJQ54KeyOYWMB0O6WreRnmFulJ3baEgAz\nYgsTPC3QBbdpngcO33dFDXg/TJkeGY9mT5HI1rBonYF1dB+AMbbCUdK5W8bA8+Ow\nhumygMscmnweEFwXT4/MvaAlelVhB0iWoAo/F4X9fEOm5dMVHzjYxTA0R0+Dzny4\nSmKlkzd3gUH4kEtgTBo8slRkO5dfg8Ik64qnQNvSidLWp9PmKkGb2069czQCyKIj\nme4sPRRl8TJQ12xVuOmlRpQ4+rUxhMfZKyyYZ0isoVNYsmeFPQ8=\n\n",
            "RecipientIds": {
                "bcc": [],
                "cc": [],
                "to": []
            }
        }
    }
}
```

#### Human Readable Output

>Date: Mon, 05 Aug 2024 08:56:00 +0000
>MIME-Version: 1.0
>Content-Disposition: attachment; filename="smime.p7m"
>Content-Type: application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"
>Content-Transfer-Encoding: base64
>
>MIIJ4gYJKoZIhvcNAQcCoIIJ0zCCCc8CAQExDzANBglghkgBZQMEAgEFADCCAUkG
>CSqGSIb3DQEHAaCCAToEggE2Q29udGVudC1UeXBlOiBtdWx0aXBhcnQvbWl4ZWQ7
>IGJvdW5kYXJ5PSI9PT09PT09PT09PT09PT0wNTEzMzU2NzMxMDg3NTk4NjkxPT0i
>DQpNSU1FLVZlcnNpb246IDEuMA0KDQotLT09PT09PT09PT09PT09PTA1MTMzNTY3
>MzEwODc1OTg2OTE9PQ0KQ29udGVudC1UeXBlOiB0ZXh0L3BsYWluOyBjaGFyc2V0
>PSJ1cy1hc2NpaSINCk1JTUUtVmVyc2lvbjogMS4wDQpDb250ZW50LVRyYW5zZmVy
>LUVuY29kaW5nOiA3Yml0DQoNClRoaXMgaXMgYSBtZXNzYWdlIHRvIHNpZ24NCi0t
>PT09PT09PT09PT09PT09MDUxMzM1NjczMTA4NzU5ODY5MT09LS0NCqCCBb0wggW5
>MIIDoaADAgECAhAWjRiNCtW2fdBrguq+Q6aTMA0GCSqGSIb3DQEBCwUAMIGBMQsw
>CQYDVQQGEwJJVDEQMA4GA1UECAwHQmVyZ2FtbzEZMBcGA1UEBwwQUG9udGUgU2Fu
>IFBpZXRybzEXMBUGA1UECgwOQWN0YWxpcyBTLnAuQS4xLDAqBgNVBAMMI0FjdGFs
>aXMgQ2xpZW50IEF1dGhlbnRpY2F0aW9uIENBIEczMB4XDTI0MDcyMTA4MzkwMFoX
>DTI1MDcyMTA4MzkwMFowJDEiMCAGA1UEAwwZc20uc21pbWUudGVzdGVyQGdtYWls
>LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcJHez4H953XJAG
>SRzfh+/HtTvqC0cu+KEeiGK/WYXuYZtjNb3Z7P++/DCZkWZ6FAMKZyMJqEwNiYsd
>dvirSdOHpfgPSKtTILiFXtTogGjPydAZvxri9x8Kg1AnyKwk4WJi3ftfgaIFpo8i
>F7BKS36IDpdb3O43mlLwXfOdWQBPlY0ndYPIWS+elbSHbHH+s8ai6CGcFoB3Akyb
>vIbSjVj5YFKky0wYVeXtJpgYlZoOFUmkCI5jpSTlCFIUm2bwIFwCeXt/hl0xHaXM
>fCPpX7B+EYLd2wUei2ZeEaDMi5Gnd9ANBlP9c8xe+KXQQ3vy1OT1ptd0YscOMz6E
>yhZLut0CAwEAAaOCAYcwggGDMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUvpep
>qoS/gL8QU30JMvnhLjIbz3cwfgYIKwYBBQUHAQEEcjBwMDsGCCsGAQUFBzAChi9o
>dHRwOi8vY2FjZXJ0LmFjdGFsaXMuaXQvY2VydHMvYWN0YWxpcy1hdXRjbGlnMzAx
>BggrBgEFBQcwAYYlaHR0cDovL29jc3AwOS5hY3RhbGlzLml0L1ZBL0FVVEhDTC1H
>MzAkBgNVHREEHTAbgRlzbS5zbWltZS50ZXN0ZXJAZ21haWwuY29tMBQGA1UdIAQN
>MAswCQYHZ4EMAQUBATAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwSAYD
>VR0fBEEwPzA9oDugOYY3aHR0cDovL2NybDA5LmFjdGFsaXMuaXQvUmVwb3NpdG9y
>eS9BVVRIQ0wtRzMvZ2V0TGFzdENSTDAdBgNVHQ4EFgQUq8xlmZF/uLyAf3JUU1Bc
>Xr+QRKMwDgYDVR0PAQH/BAQDAgWgMA0GCSqGSIb3DQEBCwUAA4ICAQCwNi6XtZwt
>e/mwEAswIi9OSHLAT7ruUNksl+RP8LdZQ9gyVxv5kER5mfdOF5ATO2OQ7Z/Y+ahs
>2Fk69tNckmq6tf4yhBGlWsHyYOLo+Njg0UVxah0NtDrbZfwqY6PeE5rcH7evYbpn
>fP25wf/5hZlqokpe+WwBTpxJLC6uRVQIdMpUKjRhpGJlRMUy7VZhzKzTqlkwAFID
>CaYAItFJ8DsVroZxq2A7g+jlrwc5tAaYglydn96HD4DOKmLPtHN3HkUrKuoXYDiN
>/ccZZ8wYRBB3zP1FjNyK8FHhjJpn70DY6sOvPn3ShzSL4vPEKYG1qABwTdToRh8v
>dZ4FlM4apSSRhZyaKGvfRzT1XlAE1zRlUWd2krNV+WXrLrs6NF0RKRtSR+IP5QmH
>KhgZJeUv2cgiOD+7Gx+7QTi0rERj9nH+jvvX1dn8kncT/PYuLBkHg1c1Xyv1o5vW
>NHfiIsqZMVUW+aZPm92k77+/AcgOaHcvqTP8vxbZBOgf959VSLma/n7NDprhjNg6
>O7pHh/cAB35gu9Q7acZE9NEwc+J0vl4LVx7YlP0aEaR8BOaFufQyOwD+2JV2f0bQ
>XwltX2Gr77xsOZKI/2pVn9Oj6xyW3h7ZrlA7Me/l4H9VAHoi6epON8r9wI+UDJKo
>Iz3nxuKNFYDgnjtIaYrX5xjprYVX3fJlAzGCAqkwggKlAgEBMIGWMIGBMQswCQYD
>VQQGEwJJVDEQMA4GA1UECAwHQmVyZ2FtbzEZMBcGA1UEBwwQUG9udGUgU2FuIFBp
>ZXRybzEXMBUGA1UECgwOQWN0YWxpcyBTLnAuQS4xLDAqBgNVBAMMI0FjdGFsaXMg
>Q2xpZW50IEF1dGhlbnRpY2F0aW9uIENBIEczAhAWjRiNCtW2fdBrguq+Q6aTMA0G
>CWCGSAFlAwQCAQUAoIHkMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI
>hvcNAQkFMQ8XDTI0MDgwNTA4NTYwMFowLwYJKoZIhvcNAQkEMSIEIJxfZpuZLFhT
>/xN2gZGCKzEPOnGX6uuyA5byB32PPlsqMHkGCSqGSIb3DQEJDzFsMGowCwYJYIZI
>AWUDBAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYI
>KoZIhvcNAwICAgCAMA0GCCqGSIb3DQMCAgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMC
>AgEoMA0GCSqGSIb3DQEBAQUABIIBAFZZ5ExsKfb+hCgY5YQcVodYC74CmcCaN6fc
>JG6jL0yDNUV7wzuUNMT/DoxhKFI/2MNNJQ54KeyOYWMB0O6WreRnmFulJ3baEgAz
>YgsTPC3QBbdpngcO33dFDXg/TJkeGY9mT5HI1rBonYF1dB+AMbbCUdK5W8bA8+Ow
>humygMscmnweEFwXT4/MvaAlelVhB0iWoAo/F4X9fEOm5dMVHzjYxTA0R0+Dzny4
>SmKlkzd3gUH4kEtgTBo8slRkO5dfg8Ik64qnQNvSidLWp9PmKkGb2069czQCyKIj
>me4sPRRl8TJQ12xVuOmlRpQ4+rUxhMfZKyyYZ0isoVNYsmeFPQ8=
>


#### Command example

```!smime-sign-and-encrypt message="This is a message to encrypt" signed=false```

#### Context Example

```json
{
    "SMIME": {
        "SignedAndEncrypted": {
            "FileName": "",
            "Message": "Date: Mon, 05 Aug 2024 08:56:03 +0000\r\nMIME-Version: 1.0\nContent-Disposition: attachment; filename=\"smime.p7m\"\nContent-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\nContent-Transfer-Encoding: base64\n\nMIIDPwYJKoZIhvcNAQcDoIIDMDCCAywCAQAxggGzMIIBrwIBADCBljCBgTELMAkG\nA1UEBhMCSVQxEDAOBgNVBAgMB0JlcmdhbW8xGTAXBgNVBAcMEFBvbnRlIFNhbiBQ\naWV0cm8xFzAVBgNVBAoMDkFjdGFsaXMgUy5wLkEuMSwwKgYDVQQDDCNBY3RhbGlz\nIENsaWVudCBBdXRoZW50aWNhdGlvbiBDQSBHMwIQFo0YjQrVtn3Qa4LqvkOmkzAN\nBgkqhkiG9w0BAQEFAASCAQDFnrTvu16smUFbTBoLJLdM+0hIcsMq66ssFc0BtihR\n6+XQXkE+VRJ6Zn1L+qfUWVUYuZvWwT9TV8CpJV4zJftqcGpyrHSsdA9HNPYMsO/c\nbnWWPfrWeqxcJrnfABIk2f8G+Tar2PcPLRn/DEs10j1ZtKGW0b6veBQowi6zHvto\nc+jY3lRqTLFxBJlvL5PpHItV3GrEorAKN+pR/nwey/xYApdQeIMOF2zt/X5sRaM0\nzaxJ7q+rlfRboxKoQIROsJGP3f7vlcKZx6VF5A3VH0B4/Wu82PNQO7NGXZymCwTo\ntz+twA72J0Dt5wRKY2NDZZnunWGnfSkrX78q9ygdLfuAMIIBbgYJKoZIhvcNAQcB\nMB0GCWCGSAFlAwQBKgQQDnYKpZW9arvx/5zUCivAq4CCAUBM+/9WJMmbRGW6btBo\nIe4S2Yp+RVOWjMSXwJF3I8ugZJ5XMsUUhssmOpIpBrGnDDq/5bn74j+tIIO9UjQm\nODnV2mxradfmh4Xpw215SY+6UcgtvhwoYkqK8X3de+jca07ER8ig0ubzXke1HPd5\n0/qYPL8FmvI2HWML1rx95Z/n07h8KRNcjKX/u5c9kaBa+CayS6T2JqWPXsjCgiuL\nZa1plhvecAWwW4RllCyiyBSQNaOV5PyMZWAd7VOqK7wD3mp9Qo9pffcOzGhB9PMr\nQZzXsSyB78JxSkXCQA+fU7E+EL4B/U04iPjaj9IxrrEN4m3Pxi8i5xG8YrzfMHE0\nKJu33MeFXApz/qZ3OwmmdYl7l8zs12LArs813yMhOpu2vicjrZ+S5BYygM1oOvr+\n+Mmk+dI+iwm16cO4MWhY6szJRQ==\n\n",
            "RecipientIds": {
                "bcc": [],
                "cc": [],
                "to": []
            }
        }
    }
}
```

#### Human Readable Output

>Date: Mon, 05 Aug 2024 08:56:03 +0000
>MIME-Version: 1.0
>Content-Disposition: attachment; filename="smime.p7m"
>Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
>Content-Transfer-Encoding: base64
>
>MIIDPwYJKoZIhvcNAQcDoIIDMDCCAywCAQAxggGzMIIBrwIBADCBljCBgTELMAkG
>A1UEBhMCSVQxEDAOBgNVBAgMB0JlcmdhbW8xGTAXBgNVBAcMEFBvbnRlIFNhbiBQ
>aWV0cm8xFzAVBgNVBAoMDkFjdGFsaXMgUy5wLkEuMSwwKgYDVQQDDCNBY3RhbGlz
>IENsaWVudCBBdXRoZW50aWNhdGlvbiBDQSBHMwIQFo0YjQrVtn3Qa4LqvkOmkzAN
>BgkqhkiG9w0BAQEFAASCAQDFnrTvu16smUFbTBoLJLdM+0hIcsMq66ssFc0BtihR
>6+XQXkE+VRJ6Zn1L+qfUWVUYuZvWwT9TV8CpJV4zJftqcGpyrHSsdA9HNPYMsO/c
>bnWWPfrWeqxcJrnfABIk2f8G+Tar2PcPLRn/DEs10j1ZtKGW0b6veBQowi6zHvto
>c+jY3lRqTLFxBJlvL5PpHItV3GrEorAKN+pR/nwey/xYApdQeIMOF2zt/X5sRaM0
>zaxJ7q+rlfRboxKoQIROsJGP3f7vlcKZx6VF5A3VH0B4/Wu82PNQO7NGXZymCwTo
>tz+twA72J0Dt5wRKY2NDZZnunWGnfSkrX78q9ygdLfuAMIIBbgYJKoZIhvcNAQcB
>MB0GCWCGSAFlAwQBKgQQDnYKpZW9arvx/5zUCivAq4CCAUBM+/9WJMmbRGW6btBo
>Ie4S2Yp+RVOWjMSXwJF3I8ugZJ5XMsUUhssmOpIpBrGnDDq/5bn74j+tIIO9UjQm
>ODnV2mxradfmh4Xpw215SY+6UcgtvhwoYkqK8X3de+jca07ER8ig0ubzXke1HPd5
>0/qYPL8FmvI2HWML1rx95Z/n07h8KRNcjKX/u5c9kaBa+CayS6T2JqWPXsjCgiuL
>Za1plhvecAWwW4RllCyiyBSQNaOV5PyMZWAd7VOqK7wD3mp9Qo9pffcOzGhB9PMr
>QZzXsSyB78JxSkXCQA+fU7E+EL4B/U04iPjaj9IxrrEN4m3Pxi8i5xG8YrzfMHE0
>KJu33MeFXApz/qZ3OwmmdYl7l8zs12LArs813yMhOpu2vicjrZ+S5BYygM1oOvr+
>+Mmk+dI+iwm16cO4MWhY6szJRQ==
>


#### Command example

```!smime-sign-and-encrypt message="This is a message to sign and encrypt"```

#### Context Example

```json
{
    "SMIME": {
        "SignedAndEncrypted": {
            "FileName": "",
            "Message": "Date: Mon, 05 Aug 2024 08:56:06 +0000\r\nMIME-Version: 1.0\nContent-Disposition: attachment; filename=\"smime.p7m\"\nContent-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\nContent-Transfer-Encoding: base64\n\n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\nkuj3\n\n",
            "RecipientIds": {
                "bcc": [],
                "cc": [],
                "to": []
            }
        }
    }
}
```

#### Human Readable Output

>Date: Mon, 05 Aug 2024 08:56:06 +0000
>MIME-Version: 1.0
>Content-Disposition: attachment; filename="smime.p7m"
>Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
>Content-Transfer-Encoding: base64
>
>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
>kuj3
>
