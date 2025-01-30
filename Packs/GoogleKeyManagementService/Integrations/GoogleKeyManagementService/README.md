Use the Google Key Management Service API for CryptoKey management and encrypt/decrypt functionality.

## Configure Google Key Management Service in Cortex


| **Parameter** | **Required** |
| --- | --- |
| User's Service Account JSON | True |
| Project in Google Cloud KMS | True |
| Default Location | True |
| Default Key Ring | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google-kms-create-key
***
Creates a new CryptoKey within a KeyRing.


#### Base Command

`google-kms-create-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the created crypto-key. It must be unique within a KeyRing and match the regular expression [a-zA-Z0-9_-]{1,63}. | Required | 
| labels | Labels with user-defined metadata. | Optional | 
| next_rotation_time | Date of the next scheduled rotation time. The Key Management Service automatically creates a new version of this CryptoKey and<br/>marks the new version as primary at the next rotation time.<br/>Key rotations performed manually through cryptoKeyVersions.create and cryptoKeys.updatePrimaryVersion do not affect nextRotationTime.<br/><br/>Keys with purpose ENCRYPT_DECRYPT support automatic rotation. For other keys, this field must be omitted.<br/><br/>A timestamp or a date in RFC3339 UTC "Zulu" format, accurate to nanoseconds. For example, "2014-10-02T15:01:23.045123456Z".<br/><br/>If left empty, it is set in 90 days. | Optional | 
| attestation | The statement that was generated and signed by the HSM at the key creation time. Use this statement to verify attributes of the key as stored on the HSM, independently of Google. Only provided for key versions with protectionLevel HSM. | Optional | 
| state | The state of a CryptoKeyVersion, indicating if it can be used. Can be: "CRYPTO_KEY_VERSION_STATE_UNSPECIFIED, "PENDING_GENERATION", "ENABLED", "DISABLED", "DESTROYED",  "DESTROY_SCHEDULED" , "PENDING_IMPORT", " IMPORT_FAILED". Possible values are: CRYPTO_KEY_VERSION_STATE_UNSPECIFIED, PENDING_GENERATION, ENABLED, DISABLED, DESTROYED, DESTROY_SCHEDULED, PENDING_IMPORT, IMPORT_FAILED. Default is ENABLED. | Optional | 
| purpose | The cryptographic capabilities of a CryptoKey. A given key can only be used for the operations allowed by its purpose. Can be: "CRYPTO_KEY_PURPOSE_UNSPECIFIED", "ENCRYPT_DECRYPT", "ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT". Possible values are: CRYPTO_KEY_PURPOSE_UNSPECIFIED, ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT. Default is ENCRYPT_DECRYPT. | Required | 
| rotation_period | The time between when new key versions are generated automatically. Must be between 24 hours and 876,000 hours. Keys with ENCRYPT_DECRYPT purpose support automatic rotation. For other keys, this field must be omitted. A duration in seconds. Default is 7776000. | Required | 
| algorithm | Algorithm to use when creating a CryptoKeyVersion based on this template. Possible values are: CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED, GOOGLE_SYMMETRIC_ENCRYPTION, RSA_SIGN_PSS_2048_SHA256, RSA_SIGN_PSS_3072_SHA256, RSA_SIGN_PSS_4096_SHA256, RSA_SIGN_PSS_4096_SHA512, RSA_SIGN_PKCS1_2048_SHA256, RSA_SIGN_PKCS1_3072_SHA256, RSA_SIGN_PKCS1_4096_SHA256, RSA_SIGN_PKCS1_4096_SHA512, RSA_DECRYPT_OAEP_2048_SHA256, RSA_DECRYPT_OAEP_3072_SHA256, RSA_DECRYPT_OAEP_4096_SHA256, RSA_DECRYPT_OAEP_4096_SHA512, EC_SIGN_P256_SHA256, EC_SIGN_P384_SHA384. Default is GOOGLE_SYMMETRIC_ENCRYPTION. | Optional | 
| protection_level | Protections levels for cryptographic operations when creating a CryptoKeyVersion. Can be: Can be: "PROECTECTION_LEVEL_UNSPECIFIED", "SOFTWARE", "HSM". Default is "SOFTWARE". Possible values are: PROTECTION_LEVEL_UNSPECIFIED, SOFTWARE, HSM. Default is SOFTWARE. | Optional | 
| skip_initial_version_creation | Whether to create a CryptoKey without any CryptoKeyVersions. You have to create the CryptoKeyVersion to use this key. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.CryptoKey.Name | String | The resource name for this CryptoKey. | 
| GoogleKMS.CryptoKey.Purpose | String | The immutable purpose of this CryptoKey. | 
| GoogleKMS.CryptoKey.CreationTime | String | The time when this CryptoKey was created. | 
| GoogleKMS.CryptoKey.NextRotationTime | Date | The date when the next scheduled rotation is due to run. At nextRotationTime, the Key Management Service automatically
creates a new version of this CryptoKey and marks the new version as primary. | 
| GoogleKMS.CryptoKey.RotationPeriod | String | The period for which the nextRotationTime is advanced, when the service automatically rotates a key. | 
| GoogleKMS.CryptoKey.Labels | String | Labels with user-defined metadata. | 
| GoogleKMS.CryptoKey.VersionTemplate.ProtectionLevel | String | The protection level describing how cryptographic operations are performed with this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.VersionTemplate.Algorithm | String | The CryptoKeyVersionAlgorithm that this CryptoKeyVersion supports. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.Name | String | The resource name for this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.State | String | The current state of the CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.CreationTime | Date | The time when this CryptoKeyVersion was created. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.ProtectionLevel | String | The ProtectionLevel describing how cryptographic operations are performed with this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.Algorithm | String | The algorithm in use in the primary CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.GenerateTime | Date | The time this CryptoKeyVersion's key material was generated. | 

### google-kms-symmetric-decrypt
***
Decrypts data that was protected by Encrypt.


#### Base Command

`google-kms-symmetric-decrypt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical region where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the crypto-key to use. | Required | 
| simple_ciphertext | The ciphertext to decrypt to simple plain text. | Optional | 
| additional_authenticated_data | A base64-encoded string passed to Cloud KMS as part of an encrypt or decrypt request.<br/>The optional data that must match the data originally supplied in the EncryptRequest.additional_authenticated_data. | Optional | 
| base64_ciphertext | The ciphertext to decrypt to base64 plain text. | Optional | 
| entry_id | The entry ID for the file to decrypt. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.SymmetricDecrypt.CryptoKey | String | The CryptoKey in use. | 
| GoogleKMS.SymmetricDecrypt.IsBase64 | Boolean | Whether the original plain text is in base64. | 
| GoogleKMS.SymmetricDecrypt.Plaintext | String | The decrypted plaintext. | 

### google-kms-symmetric-encrypt
***
Encrypts data, so it can only be recovered by a call to Decrypt.


#### Base Command

`google-kms-symmetric-encrypt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For example, https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the crypto-key to use. | Required | 
| simple_plaintext | Simple plain text to encrypt. Must be no larger than 64KiB. | Optional | 
| additional_authenticated_data | A base64-encoded string passed to Cloud KMS as part of an encrypt or decrypt request. Must also be provided during decryption through DecryptRequest.additional_authenticated_data.<br/>The maximum size depends on the key version's protection level.<br/>For SOFTWARE keys, the AAD must be no larger than 64KiB. For HSM keys, the combined length of the plain text and additionalAuthenticatedData fields must be no larger than 8KiB. | Optional | 
| base64_plaintext | The Base64 plain text to encrypt. | Optional | 
| entry_id | The entry ID for the file to encrypt. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.SymmetricEncrypt.CryptoKey | String | The CryptoKey used. | 
| GoogleKMS.SymmetricEncrypt.IsBase64 | Boolean | Whether the original plain text is in base 64. | 
| GoogleKMS.SymmetricEncrypt.Ciphertext | String | The encrypted ciphertext. | 

### google-kms-get-key
***
Returns metadata for a given CryptoKey, and its primary CryptoKeyVersion.


#### Base Command

`google-kms-get-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For example, https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' sets the location to the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the fetched crypto-key. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.CryptoKey.Name | String | The resource name for this CryptoKey. | 
| GoogleKMS.CryptoKey.Purpose | String | The immutable purpose of this CryptoKey. | 
| GoogleKMS.CryptoKey.CreationTime | Date | The time at which this CryptoKey was created. | 
| GoogleKMS.CryptoKey.NextRotationTime | Date | The date when the next scheduled rotation is due to run. At nextRotationTime, the Key Management Service automatically
creates a new version of this CryptoKey and marks the new version as primary. | 
| GoogleKMS.CryptoKey.RotationPeriod | String | The period for which the nextRotationTime is advanced, when the service automatically rotates a key. hours. | 
| GoogleKMS.CryptoKey.Labels | String | Labels with user-defined metadata. | 
| GoogleKMS.CryptoKey.VersionTemplate.ProtectionLevel | String | The ProtectionLevel describing how cryptographic operations are performed with this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.VersionTemplate.Algorithm | String | The CryptoKeyVersionAlgorithm that this CryptoKeyVersion supports. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.Name | String | The resource name for this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.State | String | The current state of the CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.CreationTime | Date | The time at which this CryptoKeyVersion was created. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.ProtectionLevel | String | The ProtectionLevel describing how cryptographic operations are performed with this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.Algorithm | String | The algorithm used in the primary CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.GenerateTime | Date | The time this CryptoKeyVersion's key material was generated. | 

### google-kms-update-key
***
Updates a CryptoKey.


#### Base Command

`google-kms-update-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the updated crypto-key. | Required | 
| next_rotation_time | The date when the next scheduled rotation is due to run. At nextRotationTime, the Key Management Service automatically<br/>creates a new version of this CryptoKey and marks the new version as primary.<br/>Key rotations performed manually via cryptoKeyVersions.create and cryptoKeys.updatePrimaryVersion do not affect nextRotationTime.<br/><br/>Keys with purpose ENCRYPT_DECRYPT, support automatic rotation. For other keys, this field must be omitted.<br/><br/>A timestamp or a date in RFC3339 UTC "Zulu" format, accurate to nanoseconds. For example, "2014-10-02T15:01:23.045123456Z". | Optional | 
| attestation | Statement that was generated and signed by the HSM at key creation time. Use this statement to verify attributes of the key as stored on the HSM, independently of Google. Only provided for key versions with protectionLevel HSM. | Optional | 
| state | The state of a CryptoKeyVersion, indicating if it can be used. Can be: "CRYPTO_KEY_VERSION_STATE_UNSPECIFIED, "PENDING_GENERATION", "ENABLED", "DISABLED", "DESTROYED",  "DESTROY_SCHEDULED" , "PENDING_IMPORT", " IMPORT_FAILED". Possible values are: CRYPTO_KEY_VERSION_STATE_UNSPECIFIED, PENDING_GENERATION, ENABLED, DISABLED, DESTROYED, DESTROY_SCHEDULED, PENDING_IMPORT, IMPORT_FAILED. | Optional | 
| purpose | CryptoKeyPurpose describes the cryptographic capabilities of a CryptoKey. A given key can only be used for the operations allowed by its purpose. Can be: "CRYPTO_KEY_PURPOSE_UNSPECIFIED", "ENCRYPT_DECRYPT", "ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT". Possible values are: CRYPTO_KEY_PURPOSE_UNSPECIFIED, ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT. | Optional | 
| rotation_period | Time between when new key versions are generated automatically. Must between 24 hours and 876,000 hours. If rotation_period is set, next_rotation_time must also be set.  Keys with purpose ENCRYPT_DECRYPT support automatic rotation. For other keys, this field must be omitted. A duration in seconds. | Optional | 
| algorithm | Algorithm to use when creating a CryptoKeyVersion based on this template. Possible values are: CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED, GOOGLE_SYMMETRIC_ENCRYPTION, RSA_SIGN_PSS_2048_SHA256, RSA_SIGN_PSS_3072_SHA256, RSA_SIGN_PSS_4096_SHA256, RSA_SIGN_PSS_4096_SHA512, RSA_SIGN_PKCS1_2048_SHA256, RSA_SIGN_PKCS1_3072_SHA256, RSA_SIGN_PKCS1_4096_SHA256, RSA_SIGN_PKCS1_4096_SHA512, RSA_DECRYPT_OAEP_2048_SHA256, RSA_DECRYPT_OAEP_3072_SHA256, RSA_DECRYPT_OAEP_4096_SHA256, RSA_DECRYPT_OAEP_4096_SHA512, EC_SIGN_P256_SHA256, EC_SIGN_P384_SHA384. | Optional | 
| protection_level | The protection_level to use when creating a CryptoKeyVersion based on this template. Can be: "PROTECTION_LEVEL_UNSPECIFIED", "SOFTWARE", "HSM". Possible values are: PROTECTION_LEVEL_UNSPECIFIED, SOFTWARE, HSM. | Optional | 
| labels | Labels with user-defined metadata. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.CryptoKey.Name | String | The resource name for this CryptoKey. | 
| GoogleKMS.CryptoKey.Purpose | String | The immutable purpose of this CryptoKey. | 
| GoogleKMS.CryptoKey.CreationTime | String | The time at which this CryptoKey was created. | 
| GoogleKMS.CryptoKey.NextRotationTime | Date | The date when the next scheduled rotation is due to run. At nextRotationTime, the Key Management Service automatically
creates a new version of this CryptoKey and marks the new version as primary. | 
| GoogleKMS.CryptoKey.RotationPeriod | String | The period for which the nextRotationTime is advanced, when the service automatically rotates a key. | 
| GoogleKMS.CryptoKey.Labels | String | Labels with user-defined metadata. | 
| GoogleKMS.CryptoKey.VersionTemplate.ProtectionLevel | String | The ProtectionLevel describing how crypto operations are performed with this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.VersionTemplate.Algorithm | String | The CryptoKeyVersionAlgorithm that this CryptoKeyVersion supports. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.Name | String | The resource name for this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.State | String | The current state of the CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.CreationTime | Date | The time at which this CryptoKeyVersion was created. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.ProtectionLevel | String | The ProtectionLevel describing how cryptographic operations are performed with this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.Algorithm | String | The algorithm in use in the primary CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.GenerateTime | Date | The time this CryptoKeyVersion's key material was generated. | 

### google-kms-destroy-key
***
Schedules a CryptoKeyVersion for destruction.


#### Base Command

`google-kms-destroy-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For example, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the crypto-key to destroy. | Required | 
| crypto_key_version | The CryptoKeyVersion ID to destroy. Use keyword 'default' to use the primary CryptoKeyVersion of the given CryptoKey. Default is default. | Required | 


#### Context Output

There is no context output for this command.
### google-kms-restore-key
***
Restores a CryptoKeyVersion in the DESTROY_SCHEDULED state.


#### Base Command

`google-kms-restore-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For example, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the crypto-key to restore. | Required | 
| crypto_key_version | The CryptoKeyVersion ID to restore. Use keyword 'default' to use the primary CryptoKeyVersion of the given CryptoKey. Default is default. | Required | 


#### Context Output

There is no context output for this command.
### google-kms-disable-key
***
Disables a CryptoKeyVersion of a given CryptoKey.


#### Base Command

`google-kms-disable-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the crypto-key to disable. | Required | 
| crypto_key_version | The CryptoKeyVersion ID to disable. Use keyword 'default' to use the primary CryptoKeyVersion of the given CryptoKey. Default is default. | Required | 


#### Context Output

There is no context output for this command.
### google-kms-enable-key
***
Enables a CryptoKeyVersion of a given CryptoKey.


#### Base Command

`google-kms-enable-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the crypto-key to enable. | Required | 
| crypto_key_version | The CryptoKeyVersion ID to enable. Use keyword 'default' to use the primary CryptoKeyVersion of the given CryptoKey. Default is default. | Required | 


#### Context Output

There is no context output for this command.
### google-kms-list-keys
***
Lists all keys in key ring.


#### Base Command

`google-kms-list-keys`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| key_state | Shows only keys with this primary CryptoKeyVersion state. Leave empty to show all. Can be: "CRYPTO_KEY_VERSION_STATE_UNSPECIFIED", "PENDING_GENERATION", "ENABLED", "DISABLED", "DESTROYED", "DESTROY_SCHEDULED", "PENDING_IMPORT", "IMPORT_FAILED". Possible values are: CRYPTO_KEY_VERSION_STATE_UNSPECIFIED, PENDING_GENERATION, ENABLED, DISABLED, DESTROYED, DESTROY_SCHEDULED, PENDING_IMPORT, IMPORT_FAILED. | Optional | 


#### Context Output

There is no context output for this command.
### google-kms-asymmetric-encrypt
***
Encrypts data using a asymmetric CryptoKey


#### Base Command

`google-kms-asymmetric-encrypt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the location to the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the crypto-key to use. | Required | 
| crypto_key_version | The CryptoKeyVersion to use. | Required | 
| simple_plaintext | Simple plain text to encrypt. Must be no larger than 64KiB. | Optional | 
| base64_plaintext | Base64 plain text to encrypt. | Optional | 
| entry_id | The entry ID of the file to encrypt. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.AsymmetricEncrypt.CryptoKey | String | The CryptoKey used | 
| GoogleKMS.AsymmetricEncrypt.IsBase64 | Boolean | Is the original plaintext in base 64 | 
| GoogleKMS.AsymmetricEncrypt.Ciphertext | String | The encrypted ciphertext | 

### google-kms-asymmetric-decrypt
***
Decrypts data using an asymmetric CryptoKey.


#### Base Command

`google-kms-asymmetric-decrypt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled, and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the crypto-key to use. | Required | 
| crypto_key_version | The CryptoKeyVersion to use. | Required | 
| simple_ciphertext | Ciphertext to decrypt to simple plain text. | Optional | 
| base64_ciphertext | Ciphertext to decrypt to base64 plain text. | Optional | 
| entry_id | The entry ID of the file to decrypt. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.AsymmetricDecrypt.CryptoKey | String | The CryptoKey in use. | 
| GoogleKMS.AsymmetricDecrypt.IsBase64 | Boolean | Whether the original plain text is in base64. | 
| GoogleKMS.AsymmetricDecrypt.Plaintext | String | The decrypted plain text. | 

### google-kms-list-key-rings
***
Lists all KeyRings in a given location.


#### Base Command

`google-kms-list-key-rings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| all | Returns all KeyRings from all locations. Default is no. Possible values are: yes, no. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.KeyRing.Name | String | The name of the KeyRing. | 
| GoogleKMS.KeyRing.CreateTime | Date | The creation time of the KeyRing. | 

### google-kms-list-all-keys
***
Lists all CryptoKeys across all KeyRings in a given location.


#### Base Command

`google-kms-list-all-keys`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| all | Whether to return all CryptoKeys from all KeyRings across all locations. Possible values are: yes, no. Default is no. | Optional | 
| key_state | Shows only keys with this primary CryptoKeyVersion state. Leave empty to show all. Possible values are: CRYPTO_KEY_VERSION_STATE_UNSPECIFIED, PENDING_GENERATION, ENABLED, DISABLED, DESTROYED, DESTROY_SCHEDULED, PENDING_IMPORT, IMPORT_FAILED. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.CryptoKey.Name | String | The resource name for this CryptoKey. | 
| GoogleKMS.CryptoKey.Purpose | String | The immutable purpose of this CryptoKey. | 
| GoogleKMS.CryptoKey.CreationTime | Date | The time at which this CryptoKey was created. | 
| GoogleKMS.CryptoKey.NextRotationTime | Date | The date when the next scheduled rotation is due to run. At nextRotationTime, the Key Management Service automatically
creates a new version of this CryptoKey and
marks the new version as primary. | 
| GoogleKMS.CryptoKey.RotationPeriod | String | The period for which the nextRotationTime is advanced, when the service automatically rotates a key. | 
| GoogleKMS.CryptoKey.Labels | String | Labels with user-defined metadata. | 
| GoogleKMS.CryptoKey.VersionTemplate.ProtectionLevel | String | The ProtectionLevel describing how crypto operations are performed with this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.VersionTemplate.Algorithm | String | The CryptoKeyVersionAlgorithm that this CryptoKeyVersion supports. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.Name | String | The resource name for this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.State | String | The current state of the CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.CreationTime | String | The time at which this CryptoKeyVersion was created. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.ProtectionLevel | String | The ProtectionLevel describing how crypto operations are performed with this CryptoKeyVersion. | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.Algorithm | String | The algorithm in use in the primary CryptoKeyVersion | 
| GoogleKMS.CryptoKey.PrimaryCryptoKeyVersion.GenerateTime | Date | The time this CryptoKeyVersion's key material was generated. | 

### google-kms-get-public-key
***
Returns the public key from a given CryptoKey.


#### Base Command

`google-kms-get-public-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The geographical regions where requests to Cloud KMS for a given resource are handled,<br/>and where the corresponding cryptographic keys are stored. For more information, see https://cloud.google.com/kms/docs/locations.<br/>Keyword 'default' uses the default location. Possible values are: default, global, asia-east1, asia-east2, asia-northeast1, asia-northeast2, asia-south1, asia-southeast1, australia-southeast1, europe-north1, europe-west1, europe-west2, europe-west3, europe-west4, europe-west6, northamerica-northeast1, us-central1, us-east1, us-east4, us-west1, us-west2, southamerica-east1, eur4, nam4, asia, europe, us. Default is default. | Required | 
| key_ring | A grouping of keys for organizational purposes.<br/>Keyword 'default' uses the default KeyRing. Default is default. | Required | 
| crypto_key | The ID for the crypto-key to use. | Required | 
| crypto_key_version | The CryptoKeyVersion to use. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleKMS.PublicKey.CryptoKey | String | The CryptoKey to which the public key is connected. | 
| GoogleKMS.PublicKey.PEM | String | The PEM of the public key. | 
| GoogleKMS.PublicKey.Algorithm | String | The algorithm used in the CryptoKey | 