Encryption Tools - Encrypt and Decrypt text and files. 

## Configure EncryptionTools on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EncryptionTools.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Required** |
   | ------------- | ------------ |
   | Public Key    | False        |
   | Private Key   | False        |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

### encryption-tools-create-keys

***
Create new RSA keys.

#### Base Command

`encryption-tools-create-keys`

#### Input

| **Argument Name** | **Description**                                                                                     | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------- | ------------ |
| nbits             | The number of bits required to store (n = p * q). Default is 512.                                   | Required     |
| override_keys     | Whether to override the current generated keys. Possible values are: true, false. Default is false. | Optional     |

#### Context Output

There is no context output for this command.

#### Command Example

```!encryption-tools-create-keys override_keys=true```

#### Human Readable Output

> Keys created successfully.

### encryption-tools-encrypt-text

***
Encrypt text.

#### Base Command

`encryption-tools-encrypt-text`

#### Input

| **Argument Name** | **Description**      | **Required** |
| ----------------- | -------------------- | ------------ |
| text_to_encrypt   | The text to encrypt. | Required     |

#### Context Output

| **Path**              | **Type** | **Description**                  |
| --------------------- | -------- | -------------------------------- |
| EncryptionTools.Value | String   | The value of the encrypted text. |

#### Command Example

```!encryption-tools-encrypt-text text_to_encrypt=XSOAR```

#### Human Readable Output

> NuWPMIT006wgl9QqGQ+aMdj0Wjmf8no9ga29I0AuWeCDVjSXtsrEq1Y0l/F0COqZKNIUFusah+nZ9QNE2p2sjA==

### encryption-tools-decrypt-text

***
Decrypt text.

#### Base Command

`encryption-tools-decrypt-text`

#### Input

| **Argument Name** | **Description**             | **Required** |
| ----------------- | --------------------------- | ------------ |
| base64_to_decrypt | The base64 text to decrypt. | Required     |

#### Context Output

There is no context output for this command.

#### Command Example

```!encryption-tools-decrypt-text base64_to_decrypt=NuWPMIT006wgl9QqGQ+aMdj0Wjmf8no9ga29I0AuWeCDVjSXtsrEq1Y0l/F0COqZKNIUFusah+nZ9QNE2p2sjA==```

#### Human Readable Output

> XSOAR

### encryption-tools-encrypt-file

***
Encrypt file.

#### Base Command

`encryption-tools-encrypt-file`

#### Input

| **Argument Name** | **Description**                                                                               | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------- | ------------ |
| entry_id          | The entry ID of the file to encrypt.                                                          | Required     |
| output_file_name  | The name of the output encrypted file. If not provided, the "encrypted" suffix will be added. | Optional     |

#### Context Output

There is no context output for this command.

#### Command Example

```!encryption-tools-encrypt-file entry_id=136@105 output_file_name=encrypted_file.txt```

#### Human Readable Output

>File Output.

### encryption-tools-decrypt-file

***
Decrypt file.

#### Base Command

`encryption-tools-decrypt-file`

#### Input

| **Argument Name** | **Description**                                                                               | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------- | ------------ |
| entry_id          | The entry ID of the file to decrypt.                                                          | Required     |
| output_file_name  | The name of the output decrypted file. If not provided, the "decrypted" suffix will be added. | Optional     |

#### Context Output

There is no context output for this command.

#### Command Example

```!encryption-tools-decrypt-file entry_id=137@105 output_file_name=decrypted_file.txt```

#### Human Readable Output

>File Output.


### encryption-tools-export-public-key

***
Exports the public key to a file.

#### Base Command

`encryption-tools-export-public-key`

#### Input

| **Argument Name** | **Description**              | **Required** |
| ----------------- | ---------------------------- | ------------ |
| output_file_name  | The name of the output file. | Required     |

#### Context Output

There is no context output for this command.

#### Command Example

```!encryption-tools-export-public-key output_file_name=public_key.txt```

#### Human Readable Output

>File Output.


### encryption-tools-export-private-key

***
Exports the private key to a file.

#### Base Command

`encryption-tools-export-private-key`

#### Input

| **Argument Name** | **Description**              | **Required** |
| ----------------- | ---------------------------- | ------------ |
| output_file_name  | The name of the output file. | Required     |

#### Context Output

There is no context output for this command.

#### Command Example

```!encryption-tools-export-private-key output_file_name=private_key.txt```

#### Human Readable Output

>File Output.