This integration enables the management of certificates on Linux hosts directly from XSOAR using Ansible. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands. This integration functions without any agents or additional software installed on the hosts by utilising SSH combined with Python.

To use this integration, configure an instance of this integration. This will associate a credential to be used to access hosts when commands are run. The commands from this integration will take the Linux host address(es) as an input, and use the saved credential associated to the instance to execute. Create separate instances if multiple credentials are required.

## Requirements
The Linux host(s) being managed requires Python >= 2.6. Different commands will use different underlying Ansible modules, and may have their own unique package requirements. Refer to the individual command documentation for further information.

## Network Requirements
By default, TCP port 22 will be used to initiate a SSH connection to the Linux host.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.

## Credentials
This integration supports a number of methods of authenticating with the Linux Host:
1. Username & Password entered into the integration
2. Username & Password credential from the XSOAR credential manager
3. Username and SSH Key from the XSOAR credential manager

## Permissions
Whilst un-privileged Linux user privileges can be used, a SuperUser account is recommended as most commands will require elevated permissions to execute.

## Privilege Escalation
Ansible can use existing privilege escalation systems to allow a user to execute tasks as another. Different from the user that logged into the machine (remote user). This is done using existing privilege escalation tools, which you probably already use or have configured, like sudo, su, or doas. Unless you are remoting into the system as root (uid 0) you will need to escalate your privileges to a super user. Use the Integration parameters `Escalate Privileges`, `Privilege Escalation Method`, `Privilege Escalation User`, `Privileges Escalation Password` to configure this.


## Concurrency
This integration supports execution of commands against multiple hosts concurrently. The `host` parameter accepts a list of addresses, and will run the command in parallel as per the **Concurrency Factor** value.

## Further information
This integration is powered by Ansible 2.9. Further information can be found on that the following locations:
* [Ansible Getting Started](https://docs.ansible.com/ansible/latest/user_guide/intro_getting_started.html)
* [Module Documentation](https://docs.ansible.com/ansible/2.9/modules/list_of_all_modules.html)

## Configure Ansible OpenSSL on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Ansible OpenSSL .
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Username | The credentials to associate with the instance. SSH keys can be configured using the credential manager. | True |
    | Password |  | True |
    | Default SSH Port | The default port to use if one is not specified in the commands \`host\` argument. | True |
    | Concurrency Factor | If multiple hosts are specified in a command, how many hosts should be interacted with concurrently. | True |

## Testing
This integration does not support testing from the integration management screen. Instead it is recommended to use the `!openssl-certificate-info` command providing an example `host` and `path` to a certificate as the command argument. This command will connect to the specified host with the configured credentials in the integration, and if successful output information about the certificate at the path.

## Complex Command Inputs
Some commands may require structured input arguments such as `lists` or `dictionary`, these can be provided in standard JSON notation wrapped in double curly braces. For example a argument called `dns_servers` that accepts a list of server IPs 8.8.8.8 and 8.8.4.4 would be entered as `dns_servers="{{ ['8.8.8.8', '8.8.4.4'] }}"`.

Other more advanced data manipulation tools such as [Ansible](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html)/[Jinja2 filters](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters) can also be used in-line. For example to get a [random number](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html#random-number-filter) between 0 and 60 you can use `{{ 60 | random }}`.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### openssl-certificate
***
Generate and/or check OpenSSL certificates
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssl_certificate_module.html


#### Base Command

`openssl-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether the certificate should exist or not, taking action if the state is different from what is stated. Possible values are: absent, present. Default is present. | Optional | 
| path | Remote absolute path where the generated certificate file should be created or is already located. | Required | 
| provider | Name of the provider to use to generate/retrieve the OpenSSL certificate.<br/>The `assertonly` provider will not generate files and fail if the certificate file is missing.<br/>The `assertonly` provider has been deprecated in Ansible 2.9 and will be removed in Ansible 2.13. Please see the examples on how to emulate it with `openssl_certificate_info`, `openssl_csr_info`, `openssl_privatekey_info` and `assert`.<br/>The `entrust` provider was added for Ansible 2.9 and requires credentials for the `https://www.entrustdatacard.com/products/categories/ssl-certificates,Entrust Certificate Services` (ECS) API.<br/>Required if `state` is `present`. Possible values are: acme, assertonly, entrust, ownca, selfsigned. | Optional | 
| force | Generate the certificate, even if it already exists. Possible values are: Yes, No. Default is No. | Optional | 
| csr_path | Path to the Certificate Signing Request (CSR) used to generate this certificate.<br/>This is not required in `assertonly` mode. | Optional | 
| privatekey_path | Path to the private key to use when signing the certificate. | Optional | 
| privatekey_passphrase | The passphrase for the `privatekey_path`.<br/>This is required if the private key is password protected. | Optional | 
| selfsigned_version | Version of the `selfsigned` certificate.<br/>Nowadays it should almost always be `3`.<br/>This is only used by the `selfsigned` provider. Default is 3. | Optional | 
| selfsigned_digest | Digest algorithm to be used when self-signing the certificate.<br/>This is only used by the `selfsigned` provider. Default is sha256. | Optional | 
| selfsigned_not_before | The point in time the certificate is valid from.<br/>Time can be specified either as relative time or as absolute timestamp.<br/>Time will always be interpreted as UTC.<br/>Valid format is `[+-]timespec \| ASN.1 TIME` where timespec can be an integer + `[w \| d \| h \| m \| s]` (e.g. `+32w1d2h`.<br/>Note that if using relative time this module is NOT idempotent.<br/>If this value is not specified, the certificate will start being valid from now.<br/>This is only used by the `selfsigned` provider. Default is +0s. | Optional | 
| selfsigned_not_after | The point in time at which the certificate stops being valid.<br/>Time can be specified either as relative time or as absolute timestamp.<br/>Time will always be interpreted as UTC.<br/>Valid format is `[+-]timespec \| ASN.1 TIME` where timespec can be an integer + `[w \| d \| h \| m \| s]` (e.g. `+32w1d2h`.<br/>Note that if using relative time this module is NOT idempotent.<br/>If this value is not specified, the certificate will stop being valid 10 years from now.<br/>This is only used by the `selfsigned` provider. Default is +3650d. | Optional | 
| selfsigned_create_subject_key_identifier | Whether to create the Subject Key Identifier (SKI) from the public key.<br/>A value of `create_if_not_provided` (default) only creates a SKI when the CSR does not provide one.<br/>A value of `always_create` always creates a SKI. If the CSR provides one, that one is ignored.<br/>A value of `never_create` never creates a SKI. If the CSR provides one, that one is used.<br/>This is only used by the `selfsigned` provider.<br/>Note that this is only supported if the `cryptography` backend is used!. Possible values are: create_if_not_provided, always_create, never_create. Default is create_if_not_provided. | Optional | 
| ownca_path | Remote absolute path of the CA (Certificate Authority) certificate.<br/>This is only used by the `ownca` provider. | Optional | 
| ownca_privatekey_path | Path to the CA (Certificate Authority) private key to use when signing the certificate.<br/>This is only used by the `ownca` provider. | Optional | 
| ownca_privatekey_passphrase | The passphrase for the `ownca_privatekey_path`.<br/>This is only used by the `ownca` provider. | Optional | 
| ownca_digest | The digest algorithm to be used for the `ownca` certificate.<br/>This is only used by the `ownca` provider. Default is sha256. | Optional | 
| ownca_version | The version of the `ownca` certificate.<br/>Nowadays it should almost always be `3`.<br/>This is only used by the `ownca` provider. Default is 3. | Optional | 
| ownca_not_before | The point in time the certificate is valid from.<br/>Time can be specified either as relative time or as absolute timestamp.<br/>Time will always be interpreted as UTC.<br/>Valid format is `[+-]timespec \| ASN.1 TIME` where timespec can be an integer + `[w \| d \| h \| m \| s]` (e.g. `+32w1d2h`.<br/>Note that if using relative time this module is NOT idempotent.<br/>If this value is not specified, the certificate will start being valid from now.<br/>This is only used by the `ownca` provider. Default is +0s. | Optional | 
| ownca_not_after | The point in time at which the certificate stops being valid.<br/>Time can be specified either as relative time or as absolute timestamp.<br/>Time will always be interpreted as UTC.<br/>Valid format is `[+-]timespec \| ASN.1 TIME` where timespec can be an integer + `[w \| d \| h \| m \| s]` (e.g. `+32w1d2h`.<br/>Note that if using relative time this module is NOT idempotent.<br/>If this value is not specified, the certificate will stop being valid 10 years from now.<br/>This is only used by the `ownca` provider. Default is +3650d. | Optional | 
| ownca_create_subject_key_identifier | Whether to create the Subject Key Identifier (SKI) from the public key.<br/>A value of `create_if_not_provided` (default) only creates a SKI when the CSR does not provide one.<br/>A value of `always_create` always creates a SKI. If the CSR provides one, that one is ignored.<br/>A value of `never_create` never creates a SKI. If the CSR provides one, that one is used.<br/>This is only used by the `ownca` provider.<br/>Note that this is only supported if the `cryptography` backend is used!. Possible values are: create_if_not_provided, always_create, never_create. Default is create_if_not_provided. | Optional | 
| ownca_create_authority_key_identifier | Create a Authority Key Identifier from the CA's certificate. If the CSR provided a authority key identifier, it is ignored.<br/>The Authority Key Identifier is generated from the CA certificate's Subject Key Identifier, if available. If it is not available, the CA certificate's public key will be used.<br/>This is only used by the `ownca` provider.<br/>Note that this is only supported if the `cryptography` backend is used!. Possible values are: Yes, No. Default is Yes. | Optional | 
| acme_accountkey_path | The path to the accountkey for the `acme` provider.<br/>This is only used by the `acme` provider. | Optional | 
| acme_challenge_path | The path to the ACME challenge directory that is served on `http://&lt;HOST&gt;:80/.well-known/acme-challenge/`<br/>This is only used by the `acme` provider. | Optional | 
| acme_chain | Include the intermediate certificate to the generated certificate<br/>This is only used by the `acme` provider.<br/>Note that this is only available for older versions of `acme-tiny`. New versions include the chain automatically, and setting `acme_chain` to `yes` results in an error. Possible values are: Yes, No. Default is No. | Optional | 
| signature_algorithms | A list of algorithms that you would accept the certificate to be signed with (e.g. ['sha256WithRSAEncryption', 'sha512WithRSAEncryption']).<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| issuer | The key/value pairs that must be present in the issuer name field of the certificate.<br/>If you need to specify more than one value with the same key, use a list as value.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| issuer_strict | If set to `yes`, the `issuer` field must contain only these values.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. Possible values are: Yes, No. Default is No. | Optional | 
| subject | The key/value pairs that must be present in the subject name field of the certificate.<br/>If you need to specify more than one value with the same key, use a list as value.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| subject_strict | If set to `yes`, the `subject` field must contain only these values.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. Possible values are: Yes, No. Default is No. | Optional | 
| has_expired | Checks if the certificate is expired/not expired at the time the module is executed.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. Possible values are: Yes, No. Default is No. | Optional | 
| version | The version of the certificate.<br/>Nowadays it should almost always be 3.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| valid_at | The certificate must be valid at this point in time.<br/>The timestamp is formatted as an ASN.1 TIME.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| invalid_at | The certificate must be invalid at this point in time.<br/>The timestamp is formatted as an ASN.1 TIME.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| not_before | The certificate must start to become valid at this point in time.<br/>The timestamp is formatted as an ASN.1 TIME.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| not_after | The certificate must expire at this point in time.<br/>The timestamp is formatted as an ASN.1 TIME.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| valid_in | The certificate must still be valid at this relative time offset from now.<br/>Valid format is `[+-]timespec \| number_of_seconds` where timespec can be an integer + `[w \| d \| h \| m \| s]` (e.g. `+32w1d2h`.<br/>Note that if using this parameter, this module is NOT idempotent.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| key_usage | The `key_usage` extension field must contain all these values.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| key_usage_strict | If set to `yes`, the `key_usage` extension field must contain only these values.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. Possible values are: Yes, No. Default is No. | Optional | 
| extended_key_usage | The `extended_key_usage` extension field must contain all these values.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| extended_key_usage_strict | If set to `yes`, the `extended_key_usage` extension field must contain only these values.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. Possible values are: Yes, No. Default is No. | Optional | 
| subject_alt_name | The `subject_alt_name` extension field must contain these values.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. | Optional | 
| subject_alt_name_strict | If set to `yes`, the `subject_alt_name` extension field must contain only these values.<br/>This is only used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. Possible values are: Yes, No. Default is No. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `pyopenssl`.<br/>If set to `pyopenssl`, will try to use the `pyOpenSSL,https://pypi.org/project/pyOpenSSL/` library.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library.<br/>Please note that the `pyopenssl` backend has been deprecated in Ansible 2.9, and will be removed in Ansible 2.13. From that point on, only the `cryptography` backend will be available. Possible values are: auto, cryptography, pyopenssl. Default is auto. | Optional | 
| backup | Create a backup file including a timestamp so you can get the original certificate back if you overwrote it with a new one by accident.<br/>This is not used by the `assertonly` provider.<br/>This option is deprecated since Ansible 2.9 and will be removed with the `assertonly` provider in Ansible 2.13. For alternatives, see the example on replacing `assertonly`. Possible values are: Yes, No. Default is No. | Optional | 
| entrust_cert_type | Specify the type of certificate requested.<br/>This is only used by the `entrust` provider. Possible values are: STANDARD_SSL, ADVANTAGE_SSL, UC_SSL, EV_SSL, WILDCARD_SSL, PRIVATE_SSL, PD_SSL, CDS_ENT_LITE, CDS_ENT_PRO, SMIME_ENT. Default is STANDARD_SSL. | Optional | 
| entrust_requester_email | The email of the requester of the certificate (for tracking purposes).<br/>This is only used by the `entrust` provider.<br/>This is required if the provider is `entrust`. | Optional | 
| entrust_requester_name | The name of the requester of the certificate (for tracking purposes).<br/>This is only used by the `entrust` provider.<br/>This is required if the provider is `entrust`. | Optional | 
| entrust_requester_phone | The phone number of the requester of the certificate (for tracking purposes).<br/>This is only used by the `entrust` provider.<br/>This is required if the provider is `entrust`. | Optional | 
| entrust_api_user | The username for authentication to the Entrust Certificate Services (ECS) API.<br/>This is only used by the `entrust` provider.<br/>This is required if the provider is `entrust`. | Optional | 
| entrust_api_key | The key (password) for authentication to the Entrust Certificate Services (ECS) API.<br/>This is only used by the `entrust` provider.<br/>This is required if the provider is `entrust`. | Optional | 
| entrust_api_client_cert_path | The path to the client certificate used to authenticate to the Entrust Certificate Services (ECS) API.<br/>This is only used by the `entrust` provider.<br/>This is required if the provider is `entrust`. | Optional | 
| entrust_api_client_cert_key_path | The path to the private key of the client certificate used to authenticate to the Entrust Certificate Services (ECS) API.<br/>This is only used by the `entrust` provider.<br/>This is required if the provider is `entrust`. | Optional | 
| entrust_not_after | The point in time at which the certificate stops being valid.<br/>Time can be specified either as relative time or as an absolute timestamp.<br/>A valid absolute time format is `ASN.1 TIME` such as `2019-06-18`.<br/>A valid relative time format is `[+-]timespec` where timespec can be an integer + `[w \| d \| h \| m \| s]`, such as `+365d` or `+32w1d2h`).<br/>Time will always be interpreted as UTC.<br/>Note that only the date (day, month, year) is supported for specifying the expiry date of the issued certificate.<br/>The full date-time is adjusted to EST (GMT -5:00) before issuance, which may result in a certificate with an expiration date one day earlier than expected if a relative time is used.<br/>The minimum certificate lifetime is 90 days, and maximum is three years.<br/>If this value is not specified, the certificate will stop being valid 365 days the date of issue.<br/>This is only used by the `entrust` provider. Default is +365d. | Optional | 
| entrust_api_specification_path | The path to the specification file defining the Entrust Certificate Services (ECS) API configuration.<br/>You can use this to keep a local copy of the specification to avoid downloading it every time the module is used.<br/>This is only used by the `entrust` provider. Default is https://cloud.entrust.net/EntrustCloud/documentation/cms-api-2.1.0.yaml. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.opensslCertificate.filename | string | Path to the generated Certificate | 
| OpenSSL.opensslCertificate.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-certificate host="123.123.123.123" path="/etc/ssl/crt/ansible.com.crt" privatekey_path="/etc/ssl/private/ansible.com.pem" csr_path="/etc/ssl/csr/www.ansible.com.csr" provider="selfsigned" ```

#### Context Example
```json
{
    "OpenSSL": {
        "opensslCertificate": {
            "changed": false,
            "csr": "/etc/ssl/csr/www.ansible.com.csr",
            "filename": "/etc/ssl/crt/ansible.com.crt",
            "host": "123.123.123.123",
            "notAfter": "20310706075859Z",
            "notBefore": "20210708075859Z",
            "privatekey": "/etc/ssl/private/ansible.com.pem",
            "serial_number": 7.301123280537633e+46,
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * csr: /etc/ssl/csr/www.ansible.com.csr
>  * filename: /etc/ssl/crt/ansible.com.crt
>  * notAfter: 20310706075859Z
>  * notBefore: 20210708075859Z
>  * privatekey: /etc/ssl/private/ansible.com.pem
>  * serial_number: 73011232805376328985612064552790767398333247880


### openssl-certificate-info
***
Provide information of OpenSSL X.509 certificates
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssl_certificate_info_module.html


#### Base Command

`openssl-certificate-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Remote absolute path where the certificate file is loaded from. | Required | 
| valid_at | A dict of names mapping to time specifications. Every time specified here will be checked whether the certificate is valid at this point. See the `valid_at` return value for informations on the result.<br/>Time can be specified either as relative time or as absolute timestamp.<br/>Time will always be interpreted as UTC.<br/>Valid format is `[+-]timespec \| ASN.1 TIME` where timespec can be an integer + `[w \| d \| h \| m \| s]` (e.g. `+32w1d2h`, and ASN.1 TIME (i.e. pattern `YYYYMMDDHHMMSSZ`). Note that all timestamps will be treated as being in UTC. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `pyopenssl`.<br/>If set to `pyopenssl`, will try to use the `pyOpenSSL,https://pypi.org/project/pyOpenSSL/` library.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library.<br/>Please note that the `pyopenssl` backend has been deprecated in Ansible 2.9, and will be removed in Ansible 2.13. From that point on, only the `cryptography` backend will be available. Possible values are: auto, cryptography, pyopenssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.opensslCertificateInfo.expired | boolean | Whether the certificate is expired \(i.e. \`notAfter\` is in the past\) | 
| OpenSSL.opensslCertificateInfo.basic_constraints | unknown | Entries in the \`basic_constraints\` extension, or \`none\` if extension is not present. | 
| OpenSSL.opensslCertificateInfo.basic_constraints_critical | boolean | Whether the \`basic_constraints\` extension is critical. | 
| OpenSSL.opensslCertificateInfo.extended_key_usage | unknown | Entries in the \`extended_key_usage\` extension, or \`none\` if extension is not present. | 
| OpenSSL.opensslCertificateInfo.extended_key_usage_critical | boolean | Whether the \`extended_key_usage\` extension is critical. | 
| OpenSSL.opensslCertificateInfo.extensions_by_oid | unknown | Returns a dictionary for every extension OID | 
| OpenSSL.opensslCertificateInfo.key_usage | string | Entries in the \`key_usage\` extension, or \`none\` if extension is not present. | 
| OpenSSL.opensslCertificateInfo.key_usage_critical | boolean | Whether the \`key_usage\` extension is critical. | 
| OpenSSL.opensslCertificateInfo.subject_alt_name | unknown | Entries in the \`subject_alt_name\` extension, or \`none\` if extension is not present. | 
| OpenSSL.opensslCertificateInfo.subject_alt_name_critical | boolean | Whether the \`subject_alt_name\` extension is critical. | 
| OpenSSL.opensslCertificateInfo.ocsp_must_staple | boolean | \`yes\` if the OCSP Must Staple extension is present, \`none\` otherwise. | 
| OpenSSL.opensslCertificateInfo.ocsp_must_staple_critical | boolean | Whether the \`ocsp_must_staple\` extension is critical. | 
| OpenSSL.opensslCertificateInfo.issuer | unknown | The certificate's issuer.
Note that for repeated values, only the last one will be returned. | 
| OpenSSL.opensslCertificateInfo.issuer_ordered | unknown | The certificate's issuer as an ordered list of tuples. | 
| OpenSSL.opensslCertificateInfo.subject | unknown | The certificate's subject as a dictionary.
Note that for repeated values, only the last one will be returned. | 
| OpenSSL.opensslCertificateInfo.subject_ordered | unknown | The certificate's subject as an ordered list of tuples. | 
| OpenSSL.opensslCertificateInfo.not_after | string | \`notAfter\` date as ASN.1 TIME | 
| OpenSSL.opensslCertificateInfo.not_before | string | \`notBefore\` date as ASN.1 TIME | 
| OpenSSL.opensslCertificateInfo.public_key | string | Certificate's public key in PEM format | 
| OpenSSL.opensslCertificateInfo.public_key_fingerprints | unknown | Fingerprints of certificate's public key.
For every hash algorithm available, the fingerprint is computed. | 
| OpenSSL.opensslCertificateInfo.signature_algorithm | string | The signature algorithm used to sign the certificate. | 
| OpenSSL.opensslCertificateInfo.serial_number | number | The certificate's serial number. | 
| OpenSSL.opensslCertificateInfo.version | number | The certificate version. | 
| OpenSSL.opensslCertificateInfo.valid_at | unknown | For every time stamp provided in the \`valid_at\` option, a boolean whether the certificate is valid at that point in time or not. | 
| OpenSSL.opensslCertificateInfo.subject_key_identifier | string | The certificate's subject key identifier.
The identifier is returned in hexadecimal, with \`:\` used to separate bytes.
Is \`none\` if the \`SubjectKeyIdentifier\` extension is not present. | 
| OpenSSL.opensslCertificateInfo.authority_key_identifier | string | The certificate's authority key identifier.
The identifier is returned in hexadecimal, with \`:\` used to separate bytes.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.opensslCertificateInfo.authority_cert_issuer | unknown | The certificate's authority cert issuer as a list of general names.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.opensslCertificateInfo.authority_cert_serial_number | number | The certificate's authority cert serial number.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.opensslCertificateInfo.ocsp_uri | string | The OCSP responder URI, if included in the certificate. Will be \`none\` if no OCSP responder URI is included. | 


#### Command Example
```!openssl-certificate-info host="123.123.123.123" path="/etc/ssl/crt/ansible.com.crt"```

#### Context Example
```json
{
    "OpenSSL": {
        "opensslCertificateInfo": {
            "authority_cert_issuer": null,
            "authority_cert_serial_number": null,
            "authority_key_identifier": null,
            "basic_constraints": null,
            "basic_constraints_critical": false,
            "changed": false,
            "expired": false,
            "extended_key_usage": null,
            "extended_key_usage_critical": false,
            "extensions_by_oid": {
                "2.5.29.14": {
                    "critical": false,
                    "value": "BBRtlXuXV61dCrNybX135iGY0y8Yxg=="
                },
                "2.5.29.17": {
                    "critical": false,
                    "value": "MBGCD3d3dy5hbnNpYmxlLmNvbQ=="
                }
            },
            "fingerprints": {
                "blake2b": "f6:59:5d:eb:02:e5:ad:d4:11:0b:e0:f3:86:4a:b6:77:7c:43:22:e7:1b:ba:83:b4:9a:29:75:d4:26:22:20:de:cf:1f:4d:ef:b3:fb:63:a6:6e:ed:3c:24:88:0b:d2:82:9d:13:03:58:a4:cc:4f:22:ac:c0:32:b7:15:a7:af:a4",
                "blake2s": "df:54:a2:dd:df:ba:d5:05:3f:63:5a:17:28:05:21:e7:28:fb:d4:53:7a:c4:f4:f3:e0:de:3b:84:fb:ad:2d:a9",
                "md5": "be:b1:4e:de:cf:c6:c1:6f:32:f5:ea:1f:f9:70:8b:10",
                "sha1": "27:76:2d:5c:cc:8a:8e:fe:a1:75:0a:10:d9:10:61:c3:96:e1:e6:1b",
                "sha224": "fe:b2:58:6a:35:ea:3d:7e:c7:b0:5d:39:23:0d:88:9a:29:0b:ca:06:e6:68:9c:77:77:19:f6:85",
                "sha256": "f3:83:d6:1c:41:9c:5c:e9:77:86:e5:6d:20:30:9c:e3:70:c7:75:f1:f8:ec:bb:4b:d1:b7:ec:8e:01:43:ae:15",
                "sha384": "fa:32:3e:9e:6f:19:0f:43:4b:4a:02:aa:46:04:81:dd:c5:ff:34:ba:ff:bd:63:fe:45:0f:42:18:c9:52:32:81:b6:83:2a:ee:6c:3f:02:e3:46:fb:1c:88:8b:7c:45:65",
                "sha3_224": "10:9a:d7:94:ae:71:7d:c1:7e:6a:f4:c8:61:90:06:ed:19:8c:c0:49:fe:cf:80:2f:9f:3a:2a:53",
                "sha3_256": "ab:2a:6d:71:ed:db:a4:e8:4e:e4:51:57:7a:53:2c:53:ba:d6:19:02:92:ef:2a:d8:25:78:00:44:d6:f8:88:5b",
                "sha3_384": "94:94:db:db:f4:da:3c:bd:73:81:79:f0:ef:2c:98:ec:e3:5c:56:bd:c7:a7:c4:d4:1a:65:45:16:76:00:1f:69:65:20:f4:0b:51:05:ce:62:07:31:1d:10:42:9f:97:82",
                "sha3_512": "dc:21:d1:be:89:06:7e:11:41:5c:a9:59:1d:e1:ac:c3:e2:eb:e4:5a:35:bb:c2:ba:d8:65:00:cb:94:32:95:e6:9f:3a:39:25:cf:c7:2c:75:51:94:bc:63:e1:7b:f0:3d:62:60:0c:5c:30:a1:62:05:9a:df:72:49:a0:3a:60:bf",
                "sha512": "6e:e6:d5:be:40:63:d0:75:b6:e3:ed:38:02:39:1a:e0:5b:6d:b7:7f:24:6e:7f:e9:fb:46:82:7f:9e:68:01:ae:74:b9:b1:47:cc:72:e1:cc:0b:09:02:c9:79:a9:4a:a1:86:66:48:d2:14:c2:1b:99:e9:80:76:af:c9:63:98:15",
                "shake_128": "e7:a6:a6:72:f8:74:1a:58:49:e4:50:84:16:27:a7:80:55:10:14:b8:ae:1c:86:88:6e:65:c9:04:d6:d3:02:c5",
                "shake_256": "c8:85:33:36:60:57:d3:4d:1f:00:dc:8a:81:49:2f:08:53:f8:21:12:4b:dc:70:3e:ef:70:30:57:b3:15:50:5b"
            },
            "host": "123.123.123.123",
            "issuer": {
                "commonName": "www.ansible.com"
            },
            "issuer_ordered": [
                [
                    "commonName",
                    "www.ansible.com"
                ]
            ],
            "key_usage": null,
            "key_usage_critical": false,
            "not_after": "20310706075859Z",
            "not_before": "20210708075859Z",
            "ocsp_must_staple": null,
            "ocsp_must_staple_critical": false,
            "ocsp_uri": null,
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2JSDcBy4bxZU7jC5I0p6\n550ylJDYog5bb60it9bK0QZ9N9pGbCSAaWf1untaYr3zrZysFcmeaQKS75utx7Mc\nUgzbiGwTgLJk2fya5cdiMTzQEAwjbnDnmOPviPabXxuR7ZImitD9HF3UkLbpoBAl\nPBPz8h0/kzfvkx+tTiZ+jbFzGqxaV1/5+4VAiaTJ30pNU3Sqk2VeuZJOfllPBYT7\njcJF113bvl/NdhkFaOwMwLwhh4R6Q44UR5aW9zZWREXm+ku46QMbfM3KWNcH0Zfn\n+mgRcFI38jxGe3oWQFgS1lW6ftcCMkobDgA618CGz1OM1QRX7h2qN+9gLCqmcPwg\nQXghLUharRdKXN7Oj9wFBXpiDPNlRyVT5WDBBmxGbZT3GTL2GyI3wButKQuD0rpm\n59+665QuQWWRxdi/bUzQjO70zcw0sMvvnoQBEVSdJPn6NabSiuooiN9barcAdBOP\nN0T27qrZkhgWPO3Cyb+wZV9NxG8PMBFp1jfDlG5mD9lUsUsitJFoS8wfWiouyaIk\n6DG301+bpxSWHxYkEMZg7D5grrq5Ziut7gC+va/Vm49KXrmheLSOI42n/LOWHYoy\nPgTOPJTDB0/S2vR2SUmtDOCs8ENpSQfg8Jl0xepK68bMEDpBlWypz+7y155iJBSp\n0c404Rh6Mlq65yD+C8l30y8CAwEAAQ==\n-----END PUBLIC KEY-----\n",
            "public_key_fingerprints": {
                "blake2b": "a4:88:49:2e:00:5e:9c:ee:fe:ae:6d:3c:0b:72:a5:f1:17:ae:5f:13:4f:14:7e:a1:37:d0:d1:61:51:c5:10:51:c6:58:d4:0c:1f:76:dc:cf:59:8f:2d:a3:0e:93:8b:f8:75:ad:85:9f:9b:6b:3b:35:26:e6:b9:83:b1:a8:8a:79",
                "blake2s": "18:5a:d0:b2:28:b9:0b:3f:76:ff:0a:be:d4:9f:62:51:47:c2:3a:5c:8f:70:5f:2d:7b:e5:ed:67:d7:bc:aa:63",
                "md5": "26:0e:77:cb:78:33:37:bf:ff:66:7e:b9:90:43:18:02",
                "sha1": "7b:d7:62:ee:39:c8:b3:87:e3:24:fe:67:f3:23:1c:45:11:d2:67:fc",
                "sha224": "b0:13:a6:ba:ec:8e:89:a3:0c:0d:51:7c:29:16:35:78:47:7f:00:be:59:ce:3d:91:6c:e6:68:d9",
                "sha256": "fc:60:36:79:8d:83:22:7d:60:34:19:6e:4f:99:dc:b8:94:c1:f4:33:3a:d2:d4:41:fb:7c:a9:62:0d:56:5d:9f",
                "sha384": "ea:db:fb:ba:0a:8e:24:b3:05:cf:5a:0f:b7:78:92:9b:5c:01:d3:13:7a:f8:86:ec:2e:79:45:da:5f:22:bf:68:c2:da:c3:02:c8:01:f6:7e:27:57:5b:03:4c:78:f8:77",
                "sha3_224": "fe:ec:48:75:d2:49:43:5b:f9:a0:a3:68:b5:ce:a6:e3:a5:13:95:0d:a3:fa:2c:3c:75:37:5e:31",
                "sha3_256": "09:bd:51:97:85:59:36:98:a5:b7:85:eb:6d:e9:15:87:ab:7c:f4:41:a0:ec:e8:8a:97:d1:a9:77:20:f6:39:9e",
                "sha3_384": "96:a0:71:78:5d:e0:88:34:fb:98:19:f0:5f:48:3c:42:58:cf:9c:58:6c:9e:27:ca:02:05:7c:03:c7:ae:cb:06:c8:79:e0:94:dd:a6:6a:c2:f4:ab:25:2b:50:d5:82:47",
                "sha3_512": "45:c5:fe:e5:71:0b:9a:7a:53:08:1b:51:1e:5e:c4:ef:6b:d3:00:6d:8a:56:e6:63:c6:bc:e7:cd:ad:85:8a:2a:3d:3e:0b:89:e0:4d:ee:21:15:c0:6d:f0:eb:60:b9:7c:6e:3b:60:f0:09:fd:3b:d5:b0:09:6d:10:7d:d0:68:91",
                "sha512": "13:85:c4:64:31:49:3e:30:56:73:55:fe:96:82:4e:7c:53:a8:ee:21:05:d8:f1:d5:1e:52:bb:96:5c:bf:ae:b9:cc:51:ae:9f:d3:98:af:1e:f0:3e:a9:b5:c4:c6:74:ef:f2:af:e2:07:02:f8:8f:d0:64:c7:34:93:ab:38:7e:ef",
                "shake_128": "da:ee:b0:2a:3d:b5:57:05:b6:ee:8d:bd:e9:d4:20:0f:54:1e:0a:e6:39:bb:de:2d:35:a8:a3:da:86:a3:f8:a3",
                "shake_256": "d6:6f:0e:34:0d:fa:bb:58:c3:db:48:ff:3c:3b:de:c6:4e:43:9f:fd:81:28:5a:01:35:5c:bf:30:85:7a:b9:ea"
            },
            "serial_number": 7.301123280537633e+46,
            "signature_algorithm": "sha256WithRSAEncryption",
            "status": "SUCCESS",
            "subject": {
                "commonName": "www.ansible.com"
            },
            "subject_alt_name": [
                "DNS:www.ansible.com"
            ],
            "subject_alt_name_critical": false,
            "subject_key_identifier": "6d:95:7b:97:57:ad:5d:0a:b3:72:6d:7d:77:e6:21:98:d3:2f:18:c6",
            "subject_ordered": [
                [
                    "commonName",
                    "www.ansible.com"
                ]
            ],
            "valid_at": {},
            "version": 3
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * authority_cert_issuer: None
>  * authority_cert_serial_number: None
>  * authority_key_identifier: None
>  * basic_constraints: None
>  * basic_constraints_critical: False
>  * changed: False
>  * expired: False
>  * extended_key_usage: None
>  * extended_key_usage_critical: False
>  * key_usage: None
>  * key_usage_critical: False
>  * not_after: 20310706075859Z
>  * not_before: 20210708075859Z
>  * ocsp_must_staple: None
>  * ocsp_must_staple_critical: False
>  * ocsp_uri: None
>  * public_key: -----BEGIN PUBLIC KEY-----
>MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2JSDcBy4bxZU7jC5I0p6
>550ylJDYog5bb60it9bK0QZ9N9pGbCSAaWf1untaYr3zrZysFcmeaQKS75utx7Mc
>UgzbiGwTgLJk2fya5cdiMTzQEAwjbnDnmOPviPabXxuR7ZImitD9HF3UkLbpoBAl
>PBPz8h0/kzfvkx+tTiZ+jbFzGqxaV1/5+4VAiaTJ30pNU3Sqk2VeuZJOfllPBYT7
>jcJF113bvl/NdhkFaOwMwLwhh4R6Q44UR5aW9zZWREXm+ku46QMbfM3KWNcH0Zfn
>+mgRcFI38jxGe3oWQFgS1lW6ftcCMkobDgA618CGz1OM1QRX7h2qN+9gLCqmcPwg
>QXghLUharRdKXN7Oj9wFBXpiDPNlRyVT5WDBBmxGbZT3GTL2GyI3wButKQuD0rpm
>59+665QuQWWRxdi/bUzQjO70zcw0sMvvnoQBEVSdJPn6NabSiuooiN9barcAdBOP
>N0T27qrZkhgWPO3Cyb+wZV9NxG8PMBFp1jfDlG5mD9lUsUsitJFoS8wfWiouyaIk
>6DG301+bpxSWHxYkEMZg7D5grrq5Ziut7gC+va/Vm49KXrmheLSOI42n/LOWHYoy
>PgTOPJTDB0/S2vR2SUmtDOCs8ENpSQfg8Jl0xepK68bMEDpBlWypz+7y155iJBSp
>0c404Rh6Mlq65yD+C8l30y8CAwEAAQ==
>-----END PUBLIC KEY-----
>
>  * serial_number: 73011232805376328985612064552790767398333247880
>  * signature_algorithm: sha256WithRSAEncryption
>  * subject_alt_name_critical: False
>  * subject_key_identifier: 6d:95:7b:97:57:ad:5d:0a:b3:72:6d:7d:77:e6:21:98:d3:2f:18:c6
>  * version: 3
>  * ## Extensions_By_Oid
>    * ### 2.5.29.14
>      * critical: False
>      * value: BBRtlXuXV61dCrNybX135iGY0y8Yxg==
>    * ### 2.5.29.17
>      * critical: False
>      * value: MBGCD3d3dy5hbnNpYmxlLmNvbQ==
>  * ## Fingerprints
>    * blake2b: f6:59:5d:eb:02:e5:ad:d4:11:0b:e0:f3:86:4a:b6:77:7c:43:22:e7:1b:ba:83:b4:9a:29:75:d4:26:22:20:de:cf:1f:4d:ef:b3:fb:63:a6:6e:ed:3c:24:88:0b:d2:82:9d:13:03:58:a4:cc:4f:22:ac:c0:32:b7:15:a7:af:a4
>    * blake2s: df:54:a2:dd:df:ba:d5:05:3f:63:5a:17:28:05:21:e7:28:fb:d4:53:7a:c4:f4:f3:e0:de:3b:84:fb:ad:2d:a9
>    * md5: be:b1:4e:de:cf:c6:c1:6f:32:f5:ea:1f:f9:70:8b:10
>    * sha1: 27:76:2d:5c:cc:8a:8e:fe:a1:75:0a:10:d9:10:61:c3:96:e1:e6:1b
>    * sha224: fe:b2:58:6a:35:ea:3d:7e:c7:b0:5d:39:23:0d:88:9a:29:0b:ca:06:e6:68:9c:77:77:19:f6:85
>    * sha256: f3:83:d6:1c:41:9c:5c:e9:77:86:e5:6d:20:30:9c:e3:70:c7:75:f1:f8:ec:bb:4b:d1:b7:ec:8e:01:43:ae:15
>    * sha384: fa:32:3e:9e:6f:19:0f:43:4b:4a:02:aa:46:04:81:dd:c5:ff:34:ba:ff:bd:63:fe:45:0f:42:18:c9:52:32:81:b6:83:2a:ee:6c:3f:02:e3:46:fb:1c:88:8b:7c:45:65
>    * sha3_224: 10:9a:d7:94:ae:71:7d:c1:7e:6a:f4:c8:61:90:06:ed:19:8c:c0:49:fe:cf:80:2f:9f:3a:2a:53
>    * sha3_256: ab:2a:6d:71:ed:db:a4:e8:4e:e4:51:57:7a:53:2c:53:ba:d6:19:02:92:ef:2a:d8:25:78:00:44:d6:f8:88:5b
>    * sha3_384: 94:94:db:db:f4:da:3c:bd:73:81:79:f0:ef:2c:98:ec:e3:5c:56:bd:c7:a7:c4:d4:1a:65:45:16:76:00:1f:69:65:20:f4:0b:51:05:ce:62:07:31:1d:10:42:9f:97:82
>    * sha3_512: dc:21:d1:be:89:06:7e:11:41:5c:a9:59:1d:e1:ac:c3:e2:eb:e4:5a:35:bb:c2:ba:d8:65:00:cb:94:32:95:e6:9f:3a:39:25:cf:c7:2c:75:51:94:bc:63:e1:7b:f0:3d:62:60:0c:5c:30:a1:62:05:9a:df:72:49:a0:3a:60:bf
>    * sha512: 6e:e6:d5:be:40:63:d0:75:b6:e3:ed:38:02:39:1a:e0:5b:6d:b7:7f:24:6e:7f:e9:fb:46:82:7f:9e:68:01:ae:74:b9:b1:47:cc:72:e1:cc:0b:09:02:c9:79:a9:4a:a1:86:66:48:d2:14:c2:1b:99:e9:80:76:af:c9:63:98:15
>    * shake_128: e7:a6:a6:72:f8:74:1a:58:49:e4:50:84:16:27:a7:80:55:10:14:b8:ae:1c:86:88:6e:65:c9:04:d6:d3:02:c5
>    * shake_256: c8:85:33:36:60:57:d3:4d:1f:00:dc:8a:81:49:2f:08:53:f8:21:12:4b:dc:70:3e:ef:70:30:57:b3:15:50:5b
>  * ## Issuer
>    * commonName: www.ansible.com
>  * ## Issuer_Ordered
>  * ## List
>    * 0: commonName
>    * 1: www.ansible.com
>  * ## Public_Key_Fingerprints
>    * blake2b: a4:88:49:2e:00:5e:9c:ee:fe:ae:6d:3c:0b:72:a5:f1:17:ae:5f:13:4f:14:7e:a1:37:d0:d1:61:51:c5:10:51:c6:58:d4:0c:1f:76:dc:cf:59:8f:2d:a3:0e:93:8b:f8:75:ad:85:9f:9b:6b:3b:35:26:e6:b9:83:b1:a8:8a:79
>    * blake2s: 18:5a:d0:b2:28:b9:0b:3f:76:ff:0a:be:d4:9f:62:51:47:c2:3a:5c:8f:70:5f:2d:7b:e5:ed:67:d7:bc:aa:63
>    * md5: 26:0e:77:cb:78:33:37:bf:ff:66:7e:b9:90:43:18:02
>    * sha1: 7b:d7:62:ee:39:c8:b3:87:e3:24:fe:67:f3:23:1c:45:11:d2:67:fc
>    * sha224: b0:13:a6:ba:ec:8e:89:a3:0c:0d:51:7c:29:16:35:78:47:7f:00:be:59:ce:3d:91:6c:e6:68:d9
>    * sha256: fc:60:36:79:8d:83:22:7d:60:34:19:6e:4f:99:dc:b8:94:c1:f4:33:3a:d2:d4:41:fb:7c:a9:62:0d:56:5d:9f
>    * sha384: ea:db:fb:ba:0a:8e:24:b3:05:cf:5a:0f:b7:78:92:9b:5c:01:d3:13:7a:f8:86:ec:2e:79:45:da:5f:22:bf:68:c2:da:c3:02:c8:01:f6:7e:27:57:5b:03:4c:78:f8:77
>    * sha3_224: fe:ec:48:75:d2:49:43:5b:f9:a0:a3:68:b5:ce:a6:e3:a5:13:95:0d:a3:fa:2c:3c:75:37:5e:31
>    * sha3_256: 09:bd:51:97:85:59:36:98:a5:b7:85:eb:6d:e9:15:87:ab:7c:f4:41:a0:ec:e8:8a:97:d1:a9:77:20:f6:39:9e
>    * sha3_384: 96:a0:71:78:5d:e0:88:34:fb:98:19:f0:5f:48:3c:42:58:cf:9c:58:6c:9e:27:ca:02:05:7c:03:c7:ae:cb:06:c8:79:e0:94:dd:a6:6a:c2:f4:ab:25:2b:50:d5:82:47
>    * sha3_512: 45:c5:fe:e5:71:0b:9a:7a:53:08:1b:51:1e:5e:c4:ef:6b:d3:00:6d:8a:56:e6:63:c6:bc:e7:cd:ad:85:8a:2a:3d:3e:0b:89:e0:4d:ee:21:15:c0:6d:f0:eb:60:b9:7c:6e:3b:60:f0:09:fd:3b:d5:b0:09:6d:10:7d:d0:68:91
>    * sha512: 13:85:c4:64:31:49:3e:30:56:73:55:fe:96:82:4e:7c:53:a8:ee:21:05:d8:f1:d5:1e:52:bb:96:5c:bf:ae:b9:cc:51:ae:9f:d3:98:af:1e:f0:3e:a9:b5:c4:c6:74:ef:f2:af:e2:07:02:f8:8f:d0:64:c7:34:93:ab:38:7e:ef
>    * shake_128: da:ee:b0:2a:3d:b5:57:05:b6:ee:8d:bd:e9:d4:20:0f:54:1e:0a:e6:39:bb:de:2d:35:a8:a3:da:86:a3:f8:a3
>    * shake_256: d6:6f:0e:34:0d:fa:bb:58:c3:db:48:ff:3c:3b:de:c6:4e:43:9f:fd:81:28:5a:01:35:5c:bf:30:85:7a:b9:ea
>  * ## Subject
>    * commonName: www.ansible.com
>  * ## Subject_Alt_Name
>    * 0: DNS:www.ansible.com
>  * ## Subject_Ordered
>  * ## List
>    * 0: commonName
>    * 1: www.ansible.com
>  * ## Valid_At


### openssl-csr
***
Generate OpenSSL Certificate Signing Request (CSR)
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssl_csr_module.html


#### Base Command

`openssl-csr`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether the certificate signing request should exist or not, taking action if the state is different from what is stated. Possible values are: absent, present. Default is present. | Optional | 
| digest | The digest used when signing the certificate signing request with the private key. Default is sha256. | Optional | 
| privatekey_path | The path to the private key to use when signing the certificate signing request.<br/>Required if `state` is `present`. | Optional | 
| privatekey_passphrase | The passphrase for the private key.<br/>This is required if the private key is password protected. | Optional | 
| version | The version of the certificate signing request.<br/>The only allowed value according to `RFC 2986,https://tools.ietf.org/html/rfc2986#section-4.1` is 1. Default is 1. | Optional | 
| force | Should the certificate signing request be forced regenerated by this ansible module. Possible values are: Yes, No. Default is No. | Optional | 
| path | The name of the file into which the generated OpenSSL certificate signing request will be written. | Required | 
| subject | Key/value pairs that will be present in the subject name field of the certificate signing request.<br/>If you need to specify more than one value with the same key, use a list as value. | Optional | 
| country_name | The countryName field of the certificate signing request subject. | Optional | 
| state_or_province_name | The stateOrProvinceName field of the certificate signing request subject. | Optional | 
| locality_name | The localityName field of the certificate signing request subject. | Optional | 
| organization_name | The organizationName field of the certificate signing request subject. | Optional | 
| organizational_unit_name | The organizationalUnitName field of the certificate signing request subject. | Optional | 
| common_name | The commonName field of the certificate signing request subject. | Optional | 
| email_address | The emailAddress field of the certificate signing request subject. | Optional | 
| subject_alt_name | SAN extension to attach to the certificate signing request.<br/>This can either be a 'comma separated string' or a YAML list.<br/>Values must be prefixed by their options. (i.e., `email`, `URI`, `DNS`, `RID`, `IP`, `dirName`, `otherName` and the ones specific to your CA)<br/>Note that if no SAN is specified, but a common name, the common name will be added as a SAN except if `useCommonNameForSAN` is set to `false`.<br/>More at `https://tools.ietf.org/html/rfc5280#section-4.2.1.6`. | Optional | 
| subject_alt_name_critical | Should the subjectAltName extension be considered as critical. | Optional | 
| use_common_name_for_san | If set to `yes`, the module will fill the common name in for `subject_alt_name` with `DNS:` prefix if no SAN is specified. Possible values are: Yes, No. Default is Yes. | Optional | 
| key_usage | This defines the purpose (e.g. encipherment, signature, certificate signing) of the key contained in the certificate. | Optional | 
| key_usage_critical | Should the keyUsage extension be considered as critical. | Optional | 
| extended_key_usage | Additional restrictions (e.g. client authentication, server authentication) on the allowed purposes for which the public key may be used. | Optional | 
| extended_key_usage_critical | Should the extkeyUsage extension be considered as critical. | Optional | 
| basic_constraints | Indicates basic constraints, such as if the certificate is a CA. | Optional | 
| basic_constraints_critical | Should the basicConstraints extension be considered as critical. | Optional | 
| ocsp_must_staple | Indicates that the certificate should contain the OCSP Must Staple extension (`https://tools.ietf.org/html/rfc7633`). | Optional | 
| ocsp_must_staple_critical | Should the OCSP Must Staple extension be considered as critical<br/>Note that according to the RFC, this extension should not be marked as critical, as old clients not knowing about OCSP Must Staple are required to reject such certificates (see `https://tools.ietf.org/html/rfc7633#section-4`). | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `pyopenssl`.<br/>If set to `pyopenssl`, will try to use the `pyOpenSSL,https://pypi.org/project/pyOpenSSL/` library.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library.<br/>Please note that the `pyopenssl` backend has been deprecated in Ansible 2.9, and will be removed in Ansible 2.13. From that point on, only the `cryptography` backend will be available. Possible values are: auto, cryptography, pyopenssl. Default is auto. | Optional | 
| backup | Create a backup file including a timestamp so you can get the original CSR back if you overwrote it with a new one by accident. Possible values are: Yes, No. Default is No. | Optional | 
| create_subject_key_identifier | Create the Subject Key Identifier from the public key.<br/>Please note that commercial CAs can ignore the value, respectively use a value of their own choice instead. Specifying this option is mostly useful for self-signed certificates or for own CAs.<br/>Note that this is only supported if the `cryptography` backend is used!. Possible values are: Yes, No. Default is No. | Optional | 
| subject_key_identifier | The subject key identifier as a hex string, where two bytes are separated by colons.<br/>Example: `00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33`<br/>Please note that commercial CAs ignore this value, respectively use a value of their own choice. Specifying this option is mostly useful for self-signed certificates or for own CAs.<br/>Note that this option can only be used if `create_subject_key_identifier` is `no`.<br/>Note that this is only supported if the `cryptography` backend is used!. | Optional | 
| authority_key_identifier | The authority key identifier as a hex string, where two bytes are separated by colons.<br/>Example: `00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33`<br/>If specified, `authority_cert_issuer` must also be specified.<br/>Please note that commercial CAs ignore this value, respectively use a value of their own choice. Specifying this option is mostly useful for self-signed certificates or for own CAs.<br/>Note that this is only supported if the `cryptography` backend is used!<br/>The `AuthorityKeyIdentifier` will only be added if at least one of `authority_key_identifier`, `authority_cert_issuer` and `authority_cert_serial_number` is specified. | Optional | 
| authority_cert_issuer | Names that will be present in the authority cert issuer field of the certificate signing request.<br/>Values must be prefixed by their options. (i.e., `email`, `URI`, `DNS`, `RID`, `IP`, `dirName`, `otherName` and the ones specific to your CA)<br/>Example: `DNS:ca.example.org`<br/>If specified, `authority_key_identifier` must also be specified.<br/>Please note that commercial CAs ignore this value, respectively use a value of their own choice. Specifying this option is mostly useful for self-signed certificates or for own CAs.<br/>Note that this is only supported if the `cryptography` backend is used!<br/>The `AuthorityKeyIdentifier` will only be added if at least one of `authority_key_identifier`, `authority_cert_issuer` and `authority_cert_serial_number` is specified. | Optional | 
| authority_cert_serial_number | The authority cert serial number.<br/>Note that this is only supported if the `cryptography` backend is used!<br/>Please note that commercial CAs ignore this value, respectively use a value of their own choice. Specifying this option is mostly useful for self-signed certificates or for own CAs.<br/>The `AuthorityKeyIdentifier` will only be added if at least one of `authority_key_identifier`, `authority_cert_issuer` and `authority_cert_serial_number` is specified. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.opensslCsr.privatekey | string | Path to the TLS/SSL private key the CSR was generated for | 
| OpenSSL.opensslCsr.filename | string | Path to the generated Certificate Signing Request | 
| OpenSSL.opensslCsr.subject | unknown | A list of the subject tuples attached to the CSR | 
| OpenSSL.opensslCsr.subjectAltName | unknown | The alternative names this CSR is valid for | 
| OpenSSL.opensslCsr.keyUsage | unknown | Purpose for which the public key may be used | 
| OpenSSL.opensslCsr.extendedKeyUsage | unknown | Additional restriction on the public key purposes | 
| OpenSSL.opensslCsr.basicConstraints | unknown | Indicates if the certificate belongs to a CA | 
| OpenSSL.opensslCsr.ocsp_must_staple | boolean | Indicates whether the certificate has the OCSP Must Staple feature enabled | 
| OpenSSL.opensslCsr.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-csr host="123.123.123.123" path="/etc/ssl/csr/www.ansible.com.csr" privatekey_path="/etc/ssl/private/ansible.com.pem" common_name="www.ansible.com" ```

#### Context Example
```json
{
    "OpenSSL": {
        "opensslCsr": {
            "basicConstraints": null,
            "changed": false,
            "extendedKeyUsage": null,
            "filename": "/etc/ssl/csr/www.ansible.com.csr",
            "host": "123.123.123.123",
            "keyUsage": null,
            "name_constraints_excluded": [],
            "name_constraints_permitted": [],
            "ocspMustStaple": false,
            "privatekey": "/etc/ssl/private/ansible.com.pem",
            "status": "SUCCESS",
            "subject": [
                [
                    "CN",
                    "www.ansible.com"
                ]
            ],
            "subjectAltName": [
                "DNS:www.ansible.com"
            ]
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * basicConstraints: None
>  * changed: False
>  * extendedKeyUsage: None
>  * filename: /etc/ssl/csr/www.ansible.com.csr
>  * keyUsage: None
>  * ocspMustStaple: False
>  * privatekey: /etc/ssl/private/ansible.com.pem
>  * ## Name_Constraints_Excluded
>  * ## Name_Constraints_Permitted
>  * ## Subject
>  * ## List
>    * 0: CN
>    * 1: www.ansible.com
>  * ## Subjectaltname
>    * 0: DNS:www.ansible.com


### openssl-csr-info
***
Provide information of OpenSSL Certificate Signing Requests (CSR)
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssl_csr_info_module.html


#### Base Command

`openssl-csr-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Remote absolute path where the CSR file is loaded from. | Required | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `pyopenssl`.<br/>If set to `pyopenssl`, will try to use the `pyOpenSSL,https://pypi.org/project/pyOpenSSL/` library.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library.<br/>Please note that the `pyopenssl` backend has been deprecated in Ansible 2.9, and will be removed in Ansible 2.13. From that point on, only the `cryptography` backend will be available. Possible values are: auto, cryptography, pyopenssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.opensslCsrInfo.signature_valid | boolean | Whether the CSR's signature is valid.
In case the check returns \`no\`, the module will fail. | 
| OpenSSL.opensslCsrInfo.basic_constraints | unknown | Entries in the \`basic_constraints\` extension, or \`none\` if extension is not present. | 
| OpenSSL.opensslCsrInfo.basic_constraints_critical | boolean | Whether the \`basic_constraints\` extension is critical. | 
| OpenSSL.opensslCsrInfo.extended_key_usage | unknown | Entries in the \`extended_key_usage\` extension, or \`none\` if extension is not present. | 
| OpenSSL.opensslCsrInfo.extended_key_usage_critical | boolean | Whether the \`extended_key_usage\` extension is critical. | 
| OpenSSL.opensslCsrInfo.extensions_by_oid | unknown | Returns a dictionary for every extension OID | 
| OpenSSL.opensslCsrInfo.key_usage | string | Entries in the \`key_usage\` extension, or \`none\` if extension is not present. | 
| OpenSSL.opensslCsrInfo.key_usage_critical | boolean | Whether the \`key_usage\` extension is critical. | 
| OpenSSL.opensslCsrInfo.subject_alt_name | unknown | Entries in the \`subject_alt_name\` extension, or \`none\` if extension is not present. | 
| OpenSSL.opensslCsrInfo.subject_alt_name_critical | boolean | Whether the \`subject_alt_name\` extension is critical. | 
| OpenSSL.opensslCsrInfo.ocsp_must_staple | boolean | \`yes\` if the OCSP Must Staple extension is present, \`none\` otherwise. | 
| OpenSSL.opensslCsrInfo.ocsp_must_staple_critical | boolean | Whether the \`ocsp_must_staple\` extension is critical. | 
| OpenSSL.opensslCsrInfo.subject | unknown | The CSR's subject as a dictionary.
Note that for repeated values, only the last one will be returned. | 
| OpenSSL.opensslCsrInfo.subject_ordered | unknown | The CSR's subject as an ordered list of tuples. | 
| OpenSSL.opensslCsrInfo.public_key | string | CSR's public key in PEM format | 
| OpenSSL.opensslCsrInfo.public_key_fingerprints | unknown | Fingerprints of CSR's public key.
For every hash algorithm available, the fingerprint is computed. | 
| OpenSSL.opensslCsrInfo.subject_key_identifier | string | The CSR's subject key identifier.
The identifier is returned in hexadecimal, with \`:\` used to separate bytes.
Is \`none\` if the \`SubjectKeyIdentifier\` extension is not present. | 
| OpenSSL.opensslCsrInfo.authority_key_identifier | string | The CSR's authority key identifier.
The identifier is returned in hexadecimal, with \`:\` used to separate bytes.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.opensslCsrInfo.authority_cert_issuer | unknown | The CSR's authority cert issuer as a list of general names.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.opensslCsrInfo.authority_cert_serial_number | number | The CSR's authority cert serial number.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 


#### Command Example
```!openssl-csr-info host="123.123.123.123" path="/etc/ssl/csr/www.ansible.com.csr"```

#### Context Example
```json
{
    "OpenSSL": {
        "opensslCsrInfo": {
            "authority_cert_issuer": null,
            "authority_cert_serial_number": null,
            "authority_key_identifier": null,
            "basic_constraints": null,
            "basic_constraints_critical": false,
            "changed": false,
            "extended_key_usage": null,
            "extended_key_usage_critical": false,
            "extensions_by_oid": {
                "2.5.29.17": {
                    "critical": false,
                    "value": "MBGCD3d3dy5hbnNpYmxlLmNvbQ=="
                }
            },
            "host": "123.123.123.123",
            "key_usage": null,
            "key_usage_critical": false,
            "name_constraints_critical": false,
            "name_constraints_excluded": null,
            "name_constraints_permitted": null,
            "ocsp_must_staple": null,
            "ocsp_must_staple_critical": false,
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2JSDcBy4bxZU7jC5I0p6\n550ylJDYog5bb60it9bK0QZ9N9pGbCSAaWf1untaYr3zrZysFcmeaQKS75utx7Mc\nUgzbiGwTgLJk2fya5cdiMTzQEAwjbnDnmOPviPabXxuR7ZImitD9HF3UkLbpoBAl\nPBPz8h0/kzfvkx+tTiZ+jbFzGqxaV1/5+4VAiaTJ30pNU3Sqk2VeuZJOfllPBYT7\njcJF113bvl/NdhkFaOwMwLwhh4R6Q44UR5aW9zZWREXm+ku46QMbfM3KWNcH0Zfn\n+mgRcFI38jxGe3oWQFgS1lW6ftcCMkobDgA618CGz1OM1QRX7h2qN+9gLCqmcPwg\nQXghLUharRdKXN7Oj9wFBXpiDPNlRyVT5WDBBmxGbZT3GTL2GyI3wButKQuD0rpm\n59+665QuQWWRxdi/bUzQjO70zcw0sMvvnoQBEVSdJPn6NabSiuooiN9barcAdBOP\nN0T27qrZkhgWPO3Cyb+wZV9NxG8PMBFp1jfDlG5mD9lUsUsitJFoS8wfWiouyaIk\n6DG301+bpxSWHxYkEMZg7D5grrq5Ziut7gC+va/Vm49KXrmheLSOI42n/LOWHYoy\nPgTOPJTDB0/S2vR2SUmtDOCs8ENpSQfg8Jl0xepK68bMEDpBlWypz+7y155iJBSp\n0c404Rh6Mlq65yD+C8l30y8CAwEAAQ==\n-----END PUBLIC KEY-----\n",
            "public_key_fingerprints": {
                "blake2b": "a4:88:49:2e:00:5e:9c:ee:fe:ae:6d:3c:0b:72:a5:f1:17:ae:5f:13:4f:14:7e:a1:37:d0:d1:61:51:c5:10:51:c6:58:d4:0c:1f:76:dc:cf:59:8f:2d:a3:0e:93:8b:f8:75:ad:85:9f:9b:6b:3b:35:26:e6:b9:83:b1:a8:8a:79",
                "blake2s": "18:5a:d0:b2:28:b9:0b:3f:76:ff:0a:be:d4:9f:62:51:47:c2:3a:5c:8f:70:5f:2d:7b:e5:ed:67:d7:bc:aa:63",
                "md5": "26:0e:77:cb:78:33:37:bf:ff:66:7e:b9:90:43:18:02",
                "sha1": "7b:d7:62:ee:39:c8:b3:87:e3:24:fe:67:f3:23:1c:45:11:d2:67:fc",
                "sha224": "b0:13:a6:ba:ec:8e:89:a3:0c:0d:51:7c:29:16:35:78:47:7f:00:be:59:ce:3d:91:6c:e6:68:d9",
                "sha256": "fc:60:36:79:8d:83:22:7d:60:34:19:6e:4f:99:dc:b8:94:c1:f4:33:3a:d2:d4:41:fb:7c:a9:62:0d:56:5d:9f",
                "sha384": "ea:db:fb:ba:0a:8e:24:b3:05:cf:5a:0f:b7:78:92:9b:5c:01:d3:13:7a:f8:86:ec:2e:79:45:da:5f:22:bf:68:c2:da:c3:02:c8:01:f6:7e:27:57:5b:03:4c:78:f8:77",
                "sha3_224": "fe:ec:48:75:d2:49:43:5b:f9:a0:a3:68:b5:ce:a6:e3:a5:13:95:0d:a3:fa:2c:3c:75:37:5e:31",
                "sha3_256": "09:bd:51:97:85:59:36:98:a5:b7:85:eb:6d:e9:15:87:ab:7c:f4:41:a0:ec:e8:8a:97:d1:a9:77:20:f6:39:9e",
                "sha3_384": "96:a0:71:78:5d:e0:88:34:fb:98:19:f0:5f:48:3c:42:58:cf:9c:58:6c:9e:27:ca:02:05:7c:03:c7:ae:cb:06:c8:79:e0:94:dd:a6:6a:c2:f4:ab:25:2b:50:d5:82:47",
                "sha3_512": "45:c5:fe:e5:71:0b:9a:7a:53:08:1b:51:1e:5e:c4:ef:6b:d3:00:6d:8a:56:e6:63:c6:bc:e7:cd:ad:85:8a:2a:3d:3e:0b:89:e0:4d:ee:21:15:c0:6d:f0:eb:60:b9:7c:6e:3b:60:f0:09:fd:3b:d5:b0:09:6d:10:7d:d0:68:91",
                "sha512": "13:85:c4:64:31:49:3e:30:56:73:55:fe:96:82:4e:7c:53:a8:ee:21:05:d8:f1:d5:1e:52:bb:96:5c:bf:ae:b9:cc:51:ae:9f:d3:98:af:1e:f0:3e:a9:b5:c4:c6:74:ef:f2:af:e2:07:02:f8:8f:d0:64:c7:34:93:ab:38:7e:ef",
                "shake_128": "da:ee:b0:2a:3d:b5:57:05:b6:ee:8d:bd:e9:d4:20:0f:54:1e:0a:e6:39:bb:de:2d:35:a8:a3:da:86:a3:f8:a3",
                "shake_256": "d6:6f:0e:34:0d:fa:bb:58:c3:db:48:ff:3c:3b:de:c6:4e:43:9f:fd:81:28:5a:01:35:5c:bf:30:85:7a:b9:ea"
            },
            "signature_valid": true,
            "status": "SUCCESS",
            "subject": {
                "commonName": "www.ansible.com"
            },
            "subject_alt_name": [
                "DNS:www.ansible.com"
            ],
            "subject_alt_name_critical": false,
            "subject_key_identifier": null,
            "subject_ordered": [
                [
                    "commonName",
                    "www.ansible.com"
                ]
            ]
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * authority_cert_issuer: None
>  * authority_cert_serial_number: None
>  * authority_key_identifier: None
>  * basic_constraints: None
>  * basic_constraints_critical: False
>  * changed: False
>  * extended_key_usage: None
>  * extended_key_usage_critical: False
>  * key_usage: None
>  * key_usage_critical: False
>  * name_constraints_critical: False
>  * name_constraints_excluded: None
>  * name_constraints_permitted: None
>  * ocsp_must_staple: None
>  * ocsp_must_staple_critical: False
>  * public_key: -----BEGIN PUBLIC KEY-----
>MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2JSDcBy4bxZU7jC5I0p6
>550ylJDYog5bb60it9bK0QZ9N9pGbCSAaWf1untaYr3zrZysFcmeaQKS75utx7Mc
>UgzbiGwTgLJk2fya5cdiMTzQEAwjbnDnmOPviPabXxuR7ZImitD9HF3UkLbpoBAl
>PBPz8h0/kzfvkx+tTiZ+jbFzGqxaV1/5+4VAiaTJ30pNU3Sqk2VeuZJOfllPBYT7
>jcJF113bvl/NdhkFaOwMwLwhh4R6Q44UR5aW9zZWREXm+ku46QMbfM3KWNcH0Zfn
>+mgRcFI38jxGe3oWQFgS1lW6ftcCMkobDgA618CGz1OM1QRX7h2qN+9gLCqmcPwg
>QXghLUharRdKXN7Oj9wFBXpiDPNlRyVT5WDBBmxGbZT3GTL2GyI3wButKQuD0rpm
>59+665QuQWWRxdi/bUzQjO70zcw0sMvvnoQBEVSdJPn6NabSiuooiN9barcAdBOP
>N0T27qrZkhgWPO3Cyb+wZV9NxG8PMBFp1jfDlG5mD9lUsUsitJFoS8wfWiouyaIk
>6DG301+bpxSWHxYkEMZg7D5grrq5Ziut7gC+va/Vm49KXrmheLSOI42n/LOWHYoy
>PgTOPJTDB0/S2vR2SUmtDOCs8ENpSQfg8Jl0xepK68bMEDpBlWypz+7y155iJBSp
>0c404Rh6Mlq65yD+C8l30y8CAwEAAQ==
>-----END PUBLIC KEY-----
>
>  * signature_valid: True
>  * subject_alt_name_critical: False
>  * subject_key_identifier: None
>  * ## Extensions_By_Oid
>    * ### 2.5.29.17
>      * critical: False
>      * value: MBGCD3d3dy5hbnNpYmxlLmNvbQ==
>  * ## Public_Key_Fingerprints
>    * blake2b: a4:88:49:2e:00:5e:9c:ee:fe:ae:6d:3c:0b:72:a5:f1:17:ae:5f:13:4f:14:7e:a1:37:d0:d1:61:51:c5:10:51:c6:58:d4:0c:1f:76:dc:cf:59:8f:2d:a3:0e:93:8b:f8:75:ad:85:9f:9b:6b:3b:35:26:e6:b9:83:b1:a8:8a:79
>    * blake2s: 18:5a:d0:b2:28:b9:0b:3f:76:ff:0a:be:d4:9f:62:51:47:c2:3a:5c:8f:70:5f:2d:7b:e5:ed:67:d7:bc:aa:63
>    * md5: 26:0e:77:cb:78:33:37:bf:ff:66:7e:b9:90:43:18:02
>    * sha1: 7b:d7:62:ee:39:c8:b3:87:e3:24:fe:67:f3:23:1c:45:11:d2:67:fc
>    * sha224: b0:13:a6:ba:ec:8e:89:a3:0c:0d:51:7c:29:16:35:78:47:7f:00:be:59:ce:3d:91:6c:e6:68:d9
>    * sha256: fc:60:36:79:8d:83:22:7d:60:34:19:6e:4f:99:dc:b8:94:c1:f4:33:3a:d2:d4:41:fb:7c:a9:62:0d:56:5d:9f
>    * sha384: ea:db:fb:ba:0a:8e:24:b3:05:cf:5a:0f:b7:78:92:9b:5c:01:d3:13:7a:f8:86:ec:2e:79:45:da:5f:22:bf:68:c2:da:c3:02:c8:01:f6:7e:27:57:5b:03:4c:78:f8:77
>    * sha3_224: fe:ec:48:75:d2:49:43:5b:f9:a0:a3:68:b5:ce:a6:e3:a5:13:95:0d:a3:fa:2c:3c:75:37:5e:31
>    * sha3_256: 09:bd:51:97:85:59:36:98:a5:b7:85:eb:6d:e9:15:87:ab:7c:f4:41:a0:ec:e8:8a:97:d1:a9:77:20:f6:39:9e
>    * sha3_384: 96:a0:71:78:5d:e0:88:34:fb:98:19:f0:5f:48:3c:42:58:cf:9c:58:6c:9e:27:ca:02:05:7c:03:c7:ae:cb:06:c8:79:e0:94:dd:a6:6a:c2:f4:ab:25:2b:50:d5:82:47
>    * sha3_512: 45:c5:fe:e5:71:0b:9a:7a:53:08:1b:51:1e:5e:c4:ef:6b:d3:00:6d:8a:56:e6:63:c6:bc:e7:cd:ad:85:8a:2a:3d:3e:0b:89:e0:4d:ee:21:15:c0:6d:f0:eb:60:b9:7c:6e:3b:60:f0:09:fd:3b:d5:b0:09:6d:10:7d:d0:68:91
>    * sha512: 13:85:c4:64:31:49:3e:30:56:73:55:fe:96:82:4e:7c:53:a8:ee:21:05:d8:f1:d5:1e:52:bb:96:5c:bf:ae:b9:cc:51:ae:9f:d3:98:af:1e:f0:3e:a9:b5:c4:c6:74:ef:f2:af:e2:07:02:f8:8f:d0:64:c7:34:93:ab:38:7e:ef
>    * shake_128: da:ee:b0:2a:3d:b5:57:05:b6:ee:8d:bd:e9:d4:20:0f:54:1e:0a:e6:39:bb:de:2d:35:a8:a3:da:86:a3:f8:a3
>    * shake_256: d6:6f:0e:34:0d:fa:bb:58:c3:db:48:ff:3c:3b:de:c6:4e:43:9f:fd:81:28:5a:01:35:5c:bf:30:85:7a:b9:ea
>  * ## Subject
>    * commonName: www.ansible.com
>  * ## Subject_Alt_Name
>    * 0: DNS:www.ansible.com
>  * ## Subject_Ordered
>  * ## List
>    * 0: commonName
>    * 1: www.ansible.com


### openssl-dhparam
***
Generate OpenSSL Diffie-Hellman Parameters
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssl_dhparam_module.html


#### Base Command

`openssl-dhparam`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether the parameters should exist or not, taking action if the state is different from what is stated. Possible values are: absent, present. Default is present. | Optional | 
| size | Size (in bits) of the generated DH-params. Default is 4096. | Optional | 
| force | Should the parameters be regenerated even it it already exists. Possible values are: Yes, No. Default is No. | Optional | 
| path | Name of the file in which the generated parameters will be saved. | Required | 
| backup | Create a backup file including a timestamp so you can get the original DH params back if you overwrote them with new ones by accident. Possible values are: Yes, No. Default is No. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.opensslDhparam.size | number | Size \(in bits\) of the Diffie-Hellman parameters. | 
| OpenSSL.opensslDhparam.filename | string | Path to the generated Diffie-Hellman parameters. | 
| OpenSSL.opensslDhparam.backup_file | string | Name of backup file created. | 




### openssl-pkcs12
***
Generate OpenSSL PKCS#12 archive
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssl_pkcs12_module.html


#### Base Command

`openssl-pkcs12`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| action | `export` or `parse` a PKCS#12. Possible values are: export, parse. Default is export. | Optional | 
| other_certificates | List of other certificates to include. Pre 2.8 this parameter was called `ca_certificates`. | Optional | 
| certificate_path | The path to read certificates and private keys from.<br/>Must be in PEM format. | Optional | 
| force | Should the file be regenerated even if it already exists. Possible values are: Yes, No. Default is No. | Optional | 
| friendly_name | Specifies the friendly name for the certificate and private key. | Optional | 
| iter_size | Number of times to repeat the encryption step. Default is 2048. | Optional | 
| maciter_size | Number of times to repeat the MAC step. Default is 1. | Optional | 
| passphrase | The PKCS#12 password. | Optional | 
| path | Filename to write the PKCS#12 file to. | Required | 
| privatekey_passphrase | Passphrase source to decrypt any input private keys with. | Optional | 
| privatekey_path | File to read private key from. | Optional | 
| state | Whether the file should exist or not. All parameters except `path` are ignored when state is `absent`. Possible values are: absent, present. Default is present. | Optional | 
| src | PKCS#12 file path to parse. | Optional | 
| backup | Create a backup file including a timestamp so you can get the original output file back if you overwrote it with a new one by accident. Possible values are: Yes, No. Default is No. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.opensslPkcs12.filename | string | Path to the generate PKCS\#12 file. | 
| OpenSSL.opensslPkcs12.privatekey | string | Path to the TLS/SSL private key the public key was generated from. | 
| OpenSSL.opensslPkcs12.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-pkcs12 host="123.123.123.123" action="export" path="/opt/certs/ansible.p12" friendly_name="raclette" privatekey_path="/etc/ssl/private/ansible.com.pem" certificate_path="/etc/ssl/crt/ansible.com.crt" other_certificates="/etc/ssl/crt/ca.crt" state="present" ```

#### Context Example
```json
{
    "OpenSSL": {
        "opensslPkcs12": {
            "changed": false,
            "filename": "/opt/certs/ansible.p12",
            "host": "123.123.123.123",
            "mode": "0400",
            "privatekey_path": "/etc/ssl/private/ansible.com.pem",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * filename: /opt/certs/ansible.p12
>  * mode: 0400
>  * privatekey_path: /etc/ssl/private/ansible.com.pem


### openssl-privatekey
***
Generate OpenSSL private keys
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssl_privatekey_module.html


#### Base Command

`openssl-privatekey`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether the private key should exist or not, taking action if the state is different from what is stated. Possible values are: absent, present. Default is present. | Optional | 
| size | Size (in bits) of the TLS/SSL key to generate. Default is 4096. | Optional | 
| type | The algorithm used to generate the TLS/SSL private key.<br/>Note that `ECC`, `X25519`, `X448`, `Ed25519` and `Ed448` require the `cryptography` backend. `X25519` needs cryptography 2.5 or newer, while `X448`, `Ed25519` and `Ed448` require cryptography 2.6 or newer. For `ECC`, the minimal cryptography version required depends on the `curve` option. Possible values are: DSA, ECC, Ed25519, Ed448, RSA, X25519, X448. Default is RSA. | Optional | 
| curve | Note that not all curves are supported by all versions of `cryptography`.<br/>For maximal interoperability, `secp384r1` or `secp256r1` should be used.<br/>We use the curve names as defined in the `IANA registry for TLS,https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8`. Possible values are: secp384r1, secp521r1, secp224r1, secp192r1, secp256r1, secp256k1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, sect571k1, sect409k1, sect283k1, sect233k1, sect163k1, sect571r1, sect409r1, sect283r1, sect233r1, sect163r2. | Optional | 
| force | Should the key be regenerated even if it already exists. Possible values are: Yes, No. Default is No. | Optional | 
| path | Name of the file in which the generated TLS/SSL private key will be written. It will have 0600 mode. | Required | 
| passphrase | The passphrase for the private key. | Optional | 
| cipher | The cipher to encrypt the private key. (Valid values can be found by running `openssl list -cipher-algorithms` or `openssl list-cipher-algorithms`, depending on your OpenSSL version.)<br/>When using the `cryptography` backend, use `auto`. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `pyopenssl`.<br/>If set to `pyopenssl`, will try to use the `pyOpenSSL,https://pypi.org/project/pyOpenSSL/` library.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library.<br/>Please note that the `pyopenssl` backend has been deprecated in Ansible 2.9, and will be removed in Ansible 2.13. From that point on, only the `cryptography` backend will be available. Possible values are: auto, cryptography, pyopenssl. Default is auto. | Optional | 
| backup | Create a backup file including a timestamp so you can get the original private key back if you overwrote it with a new one by accident. Possible values are: Yes, No. Default is No. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.opensslPrivatekey.size | number | Size \(in bits\) of the TLS/SSL private key. | 
| OpenSSL.opensslPrivatekey.type | string | Algorithm used to generate the TLS/SSL private key. | 
| OpenSSL.opensslPrivatekey.curve | string | Elliptic curve used to generate the TLS/SSL private key. | 
| OpenSSL.opensslPrivatekey.filename | string | Path to the generated TLS/SSL private key file. | 
| OpenSSL.opensslPrivatekey.fingerprint | unknown | The fingerprint of the public key. Fingerprint will be generated for each \`hashlib.algorithms\` available.
The PyOpenSSL backend requires PyOpenSSL &gt;= 16.0 for meaningful output. | 
| OpenSSL.opensslPrivatekey.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-privatekey host="123.123.123.123" path="/etc/ssl/private/ansible.com.pem" ```

#### Context Example
```json
{
    "OpenSSL": {
        "opensslPrivatekey": {
            "changed": false,
            "filename": "/etc/ssl/private/ansible.com.pem",
            "fingerprint": {
                "blake2b": "a4:88:49:2e:00:5e:9c:ee:fe:ae:6d:3c:0b:72:a5:f1:17:ae:5f:13:4f:14:7e:a1:37:d0:d1:61:51:c5:10:51:c6:58:d4:0c:1f:76:dc:cf:59:8f:2d:a3:0e:93:8b:f8:75:ad:85:9f:9b:6b:3b:35:26:e6:b9:83:b1:a8:8a:79",
                "blake2s": "18:5a:d0:b2:28:b9:0b:3f:76:ff:0a:be:d4:9f:62:51:47:c2:3a:5c:8f:70:5f:2d:7b:e5:ed:67:d7:bc:aa:63",
                "md5": "26:0e:77:cb:78:33:37:bf:ff:66:7e:b9:90:43:18:02",
                "sha1": "7b:d7:62:ee:39:c8:b3:87:e3:24:fe:67:f3:23:1c:45:11:d2:67:fc",
                "sha224": "b0:13:a6:ba:ec:8e:89:a3:0c:0d:51:7c:29:16:35:78:47:7f:00:be:59:ce:3d:91:6c:e6:68:d9",
                "sha256": "fc:60:36:79:8d:83:22:7d:60:34:19:6e:4f:99:dc:b8:94:c1:f4:33:3a:d2:d4:41:fb:7c:a9:62:0d:56:5d:9f",
                "sha384": "ea:db:fb:ba:0a:8e:24:b3:05:cf:5a:0f:b7:78:92:9b:5c:01:d3:13:7a:f8:86:ec:2e:79:45:da:5f:22:bf:68:c2:da:c3:02:c8:01:f6:7e:27:57:5b:03:4c:78:f8:77",
                "sha3_224": "fe:ec:48:75:d2:49:43:5b:f9:a0:a3:68:b5:ce:a6:e3:a5:13:95:0d:a3:fa:2c:3c:75:37:5e:31",
                "sha3_256": "09:bd:51:97:85:59:36:98:a5:b7:85:eb:6d:e9:15:87:ab:7c:f4:41:a0:ec:e8:8a:97:d1:a9:77:20:f6:39:9e",
                "sha3_384": "96:a0:71:78:5d:e0:88:34:fb:98:19:f0:5f:48:3c:42:58:cf:9c:58:6c:9e:27:ca:02:05:7c:03:c7:ae:cb:06:c8:79:e0:94:dd:a6:6a:c2:f4:ab:25:2b:50:d5:82:47",
                "sha3_512": "45:c5:fe:e5:71:0b:9a:7a:53:08:1b:51:1e:5e:c4:ef:6b:d3:00:6d:8a:56:e6:63:c6:bc:e7:cd:ad:85:8a:2a:3d:3e:0b:89:e0:4d:ee:21:15:c0:6d:f0:eb:60:b9:7c:6e:3b:60:f0:09:fd:3b:d5:b0:09:6d:10:7d:d0:68:91",
                "sha512": "13:85:c4:64:31:49:3e:30:56:73:55:fe:96:82:4e:7c:53:a8:ee:21:05:d8:f1:d5:1e:52:bb:96:5c:bf:ae:b9:cc:51:ae:9f:d3:98:af:1e:f0:3e:a9:b5:c4:c6:74:ef:f2:af:e2:07:02:f8:8f:d0:64:c7:34:93:ab:38:7e:ef",
                "shake_128": "da:ee:b0:2a:3d:b5:57:05:b6:ee:8d:bd:e9:d4:20:0f:54:1e:0a:e6:39:bb:de:2d:35:a8:a3:da:86:a3:f8:a3",
                "shake_256": "d6:6f:0e:34:0d:fa:bb:58:c3:db:48:ff:3c:3b:de:c6:4e:43:9f:fd:81:28:5a:01:35:5c:bf:30:85:7a:b9:ea"
            },
            "host": "123.123.123.123",
            "size": 4096,
            "status": "SUCCESS",
            "type": "RSA"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * filename: /etc/ssl/private/ansible.com.pem
>  * size: 4096
>  * type: RSA
>  * ## Fingerprint
>    * blake2b: a4:88:49:2e:00:5e:9c:ee:fe:ae:6d:3c:0b:72:a5:f1:17:ae:5f:13:4f:14:7e:a1:37:d0:d1:61:51:c5:10:51:c6:58:d4:0c:1f:76:dc:cf:59:8f:2d:a3:0e:93:8b:f8:75:ad:85:9f:9b:6b:3b:35:26:e6:b9:83:b1:a8:8a:79
>    * blake2s: 18:5a:d0:b2:28:b9:0b:3f:76:ff:0a:be:d4:9f:62:51:47:c2:3a:5c:8f:70:5f:2d:7b:e5:ed:67:d7:bc:aa:63
>    * md5: 26:0e:77:cb:78:33:37:bf:ff:66:7e:b9:90:43:18:02
>    * sha1: 7b:d7:62:ee:39:c8:b3:87:e3:24:fe:67:f3:23:1c:45:11:d2:67:fc
>    * sha224: b0:13:a6:ba:ec:8e:89:a3:0c:0d:51:7c:29:16:35:78:47:7f:00:be:59:ce:3d:91:6c:e6:68:d9
>    * sha256: fc:60:36:79:8d:83:22:7d:60:34:19:6e:4f:99:dc:b8:94:c1:f4:33:3a:d2:d4:41:fb:7c:a9:62:0d:56:5d:9f
>    * sha384: ea:db:fb:ba:0a:8e:24:b3:05:cf:5a:0f:b7:78:92:9b:5c:01:d3:13:7a:f8:86:ec:2e:79:45:da:5f:22:bf:68:c2:da:c3:02:c8:01:f6:7e:27:57:5b:03:4c:78:f8:77
>    * sha3_224: fe:ec:48:75:d2:49:43:5b:f9:a0:a3:68:b5:ce:a6:e3:a5:13:95:0d:a3:fa:2c:3c:75:37:5e:31
>    * sha3_256: 09:bd:51:97:85:59:36:98:a5:b7:85:eb:6d:e9:15:87:ab:7c:f4:41:a0:ec:e8:8a:97:d1:a9:77:20:f6:39:9e
>    * sha3_384: 96:a0:71:78:5d:e0:88:34:fb:98:19:f0:5f:48:3c:42:58:cf:9c:58:6c:9e:27:ca:02:05:7c:03:c7:ae:cb:06:c8:79:e0:94:dd:a6:6a:c2:f4:ab:25:2b:50:d5:82:47
>    * sha3_512: 45:c5:fe:e5:71:0b:9a:7a:53:08:1b:51:1e:5e:c4:ef:6b:d3:00:6d:8a:56:e6:63:c6:bc:e7:cd:ad:85:8a:2a:3d:3e:0b:89:e0:4d:ee:21:15:c0:6d:f0:eb:60:b9:7c:6e:3b:60:f0:09:fd:3b:d5:b0:09:6d:10:7d:d0:68:91
>    * sha512: 13:85:c4:64:31:49:3e:30:56:73:55:fe:96:82:4e:7c:53:a8:ee:21:05:d8:f1:d5:1e:52:bb:96:5c:bf:ae:b9:cc:51:ae:9f:d3:98:af:1e:f0:3e:a9:b5:c4:c6:74:ef:f2:af:e2:07:02:f8:8f:d0:64:c7:34:93:ab:38:7e:ef
>    * shake_128: da:ee:b0:2a:3d:b5:57:05:b6:ee:8d:bd:e9:d4:20:0f:54:1e:0a:e6:39:bb:de:2d:35:a8:a3:da:86:a3:f8:a3
>    * shake_256: d6:6f:0e:34:0d:fa:bb:58:c3:db:48:ff:3c:3b:de:c6:4e:43:9f:fd:81:28:5a:01:35:5c:bf:30:85:7a:b9:ea


### openssl-privatekey-info
***
Provide information for OpenSSL private keys
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssl_privatekey_info_module.html


#### Base Command

`openssl-privatekey-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Remote absolute path where the private key file is loaded from. | Required | 
| passphrase | The passphrase for the private key. | Optional | 
| return_private_key_data | Whether to return private key data.<br/>Only set this to `yes` when you want private information about this key to leave the remote machine.<br/>WARNING: you have to make sure that private key data isn't accidentally logged!. Possible values are: Yes, No. Default is No. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `pyopenssl`.<br/>If set to `pyopenssl`, will try to use the `pyOpenSSL,https://pypi.org/project/pyOpenSSL/` library.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library.<br/>Please note that the `pyopenssl` backend has been deprecated in Ansible 2.9, and will be removed in Ansible 2.13. From that point on, only the `cryptography` backend will be available. Possible values are: auto, cryptography, pyopenssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.opensslPrivatekeyInfo.can_load_key | boolean | Whether the module was able to load the private key from disk | 
| OpenSSL.opensslPrivatekeyInfo.can_parse_key | boolean | Whether the module was able to parse the private key | 
| OpenSSL.opensslPrivatekeyInfo.key_is_consistent | boolean | Whether the key is consistent. Can also return \`none\` next to \`yes\` and \`no\`, to indicate that consistency couldn't be checked.
In case the check returns \`no\`, the module will fail. | 
| OpenSSL.opensslPrivatekeyInfo.public_key | string | Private key's public key in PEM format | 
| OpenSSL.opensslPrivatekeyInfo.public_key_fingerprints | unknown | Fingerprints of private key's public key.
For every hash algorithm available, the fingerprint is computed. | 
| OpenSSL.opensslPrivatekeyInfo.type | string | The key's type.
One of \`RSA\`, \`DSA\`, \`ECC\`, \`Ed25519\`, \`X25519\`, \`Ed448\`, or \`X448\`.
Will start with \`unknown\` if the key type cannot be determined. | 
| OpenSSL.opensslPrivatekeyInfo.public_data | unknown | Public key data. Depends on key type. | 
| OpenSSL.opensslPrivatekeyInfo.private_data | unknown | Private key data. Depends on key type. | 


### openssl-publickey
***
Generate an OpenSSL public key from its private key.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssl_publickey_module.html


#### Base Command

`openssl-publickey`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether the public key should exist or not, taking action if the state is different from what is stated. Possible values are: absent, present. Default is present. | Optional | 
| force | Should the key be regenerated even it it already exists. Possible values are: Yes, No. Default is No. | Optional | 
| format | The format of the public key. Possible values are: OpenSSH, PEM. Default is PEM. | Optional | 
| path | Name of the file in which the generated TLS/SSL public key will be written. | Required | 
| privatekey_path | Path to the TLS/SSL private key from which to generate the public key.<br/>Required if `state` is `present`. | Optional | 
| privatekey_passphrase | The passphrase for the private key. | Optional | 
| backup | Create a backup file including a timestamp so you can get the original public key back if you overwrote it with a different one by accident. Possible values are: Yes, No. Default is No. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `pyopenssl`.<br/>If set to `pyopenssl`, will try to use the `pyOpenSSL,https://pypi.org/project/pyOpenSSL/` library.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, pyopenssl. Default is auto. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.opensslPublickey.privatekey | string | Path to the TLS/SSL private key the public key was generated from. | 
| OpenSSL.opensslPublickey.format | string | The format of the public key \(PEM, OpenSSH, ...\). | 
| OpenSSL.opensslPublickey.filename | string | Path to the generated TLS/SSL public key file. | 
| OpenSSL.opensslPublickey.fingerprint | unknown | The fingerprint of the public key. Fingerprint will be generated for each hashlib.algorithms available.
Requires PyOpenSSL &gt;= 16.0 for meaningful output. | 
| OpenSSL.opensslPublickey.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-publickey host="123.123.123.123" path="/etc/ssl/public/ansible.com.pem" privatekey_path="/etc/ssl/private/ansible.com.pem" ```

#### Context Example
```json
{
    "OpenSSL": {
        "opensslPublickey": {
            "changed": false,
            "filename": "/etc/ssl/public/ansible.com.pem",
            "fingerprint": {
                "blake2b": "a4:88:49:2e:00:5e:9c:ee:fe:ae:6d:3c:0b:72:a5:f1:17:ae:5f:13:4f:14:7e:a1:37:d0:d1:61:51:c5:10:51:c6:58:d4:0c:1f:76:dc:cf:59:8f:2d:a3:0e:93:8b:f8:75:ad:85:9f:9b:6b:3b:35:26:e6:b9:83:b1:a8:8a:79",
                "blake2s": "18:5a:d0:b2:28:b9:0b:3f:76:ff:0a:be:d4:9f:62:51:47:c2:3a:5c:8f:70:5f:2d:7b:e5:ed:67:d7:bc:aa:63",
                "md5": "26:0e:77:cb:78:33:37:bf:ff:66:7e:b9:90:43:18:02",
                "sha1": "7b:d7:62:ee:39:c8:b3:87:e3:24:fe:67:f3:23:1c:45:11:d2:67:fc",
                "sha224": "b0:13:a6:ba:ec:8e:89:a3:0c:0d:51:7c:29:16:35:78:47:7f:00:be:59:ce:3d:91:6c:e6:68:d9",
                "sha256": "fc:60:36:79:8d:83:22:7d:60:34:19:6e:4f:99:dc:b8:94:c1:f4:33:3a:d2:d4:41:fb:7c:a9:62:0d:56:5d:9f",
                "sha384": "ea:db:fb:ba:0a:8e:24:b3:05:cf:5a:0f:b7:78:92:9b:5c:01:d3:13:7a:f8:86:ec:2e:79:45:da:5f:22:bf:68:c2:da:c3:02:c8:01:f6:7e:27:57:5b:03:4c:78:f8:77",
                "sha3_224": "fe:ec:48:75:d2:49:43:5b:f9:a0:a3:68:b5:ce:a6:e3:a5:13:95:0d:a3:fa:2c:3c:75:37:5e:31",
                "sha3_256": "09:bd:51:97:85:59:36:98:a5:b7:85:eb:6d:e9:15:87:ab:7c:f4:41:a0:ec:e8:8a:97:d1:a9:77:20:f6:39:9e",
                "sha3_384": "96:a0:71:78:5d:e0:88:34:fb:98:19:f0:5f:48:3c:42:58:cf:9c:58:6c:9e:27:ca:02:05:7c:03:c7:ae:cb:06:c8:79:e0:94:dd:a6:6a:c2:f4:ab:25:2b:50:d5:82:47",
                "sha3_512": "45:c5:fe:e5:71:0b:9a:7a:53:08:1b:51:1e:5e:c4:ef:6b:d3:00:6d:8a:56:e6:63:c6:bc:e7:cd:ad:85:8a:2a:3d:3e:0b:89:e0:4d:ee:21:15:c0:6d:f0:eb:60:b9:7c:6e:3b:60:f0:09:fd:3b:d5:b0:09:6d:10:7d:d0:68:91",
                "sha512": "13:85:c4:64:31:49:3e:30:56:73:55:fe:96:82:4e:7c:53:a8:ee:21:05:d8:f1:d5:1e:52:bb:96:5c:bf:ae:b9:cc:51:ae:9f:d3:98:af:1e:f0:3e:a9:b5:c4:c6:74:ef:f2:af:e2:07:02:f8:8f:d0:64:c7:34:93:ab:38:7e:ef",
                "shake_128": "da:ee:b0:2a:3d:b5:57:05:b6:ee:8d:bd:e9:d4:20:0f:54:1e:0a:e6:39:bb:de:2d:35:a8:a3:da:86:a3:f8:a3",
                "shake_256": "d6:6f:0e:34:0d:fa:bb:58:c3:db:48:ff:3c:3b:de:c6:4e:43:9f:fd:81:28:5a:01:35:5c:bf:30:85:7a:b9:ea"
            },
            "format": "PEM",
            "host": "123.123.123.123",
            "privatekey": "/etc/ssl/private/ansible.com.pem",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * filename: /etc/ssl/public/ansible.com.pem
>  * format: PEM
>  * privatekey: /etc/ssl/private/ansible.com.pem
>  * ## Fingerprint
>    * blake2b: a4:88:49:2e:00:5e:9c:ee:fe:ae:6d:3c:0b:72:a5:f1:17:ae:5f:13:4f:14:7e:a1:37:d0:d1:61:51:c5:10:51:c6:58:d4:0c:1f:76:dc:cf:59:8f:2d:a3:0e:93:8b:f8:75:ad:85:9f:9b:6b:3b:35:26:e6:b9:83:b1:a8:8a:79
>    * blake2s: 18:5a:d0:b2:28:b9:0b:3f:76:ff:0a:be:d4:9f:62:51:47:c2:3a:5c:8f:70:5f:2d:7b:e5:ed:67:d7:bc:aa:63
>    * md5: 26:0e:77:cb:78:33:37:bf:ff:66:7e:b9:90:43:18:02
>    * sha1: 7b:d7:62:ee:39:c8:b3:87:e3:24:fe:67:f3:23:1c:45:11:d2:67:fc
>    * sha224: b0:13:a6:ba:ec:8e:89:a3:0c:0d:51:7c:29:16:35:78:47:7f:00:be:59:ce:3d:91:6c:e6:68:d9
>    * sha256: fc:60:36:79:8d:83:22:7d:60:34:19:6e:4f:99:dc:b8:94:c1:f4:33:3a:d2:d4:41:fb:7c:a9:62:0d:56:5d:9f
>    * sha384: ea:db:fb:ba:0a:8e:24:b3:05:cf:5a:0f:b7:78:92:9b:5c:01:d3:13:7a:f8:86:ec:2e:79:45:da:5f:22:bf:68:c2:da:c3:02:c8:01:f6:7e:27:57:5b:03:4c:78:f8:77
>    * sha3_224: fe:ec:48:75:d2:49:43:5b:f9:a0:a3:68:b5:ce:a6:e3:a5:13:95:0d:a3:fa:2c:3c:75:37:5e:31
>    * sha3_256: 09:bd:51:97:85:59:36:98:a5:b7:85:eb:6d:e9:15:87:ab:7c:f4:41:a0:ec:e8:8a:97:d1:a9:77:20:f6:39:9e
>    * sha3_384: 96:a0:71:78:5d:e0:88:34:fb:98:19:f0:5f:48:3c:42:58:cf:9c:58:6c:9e:27:ca:02:05:7c:03:c7:ae:cb:06:c8:79:e0:94:dd:a6:6a:c2:f4:ab:25:2b:50:d5:82:47
>    * sha3_512: 45:c5:fe:e5:71:0b:9a:7a:53:08:1b:51:1e:5e:c4:ef:6b:d3:00:6d:8a:56:e6:63:c6:bc:e7:cd:ad:85:8a:2a:3d:3e:0b:89:e0:4d:ee:21:15:c0:6d:f0:eb:60:b9:7c:6e:3b:60:f0:09:fd:3b:d5:b0:09:6d:10:7d:d0:68:91
>    * sha512: 13:85:c4:64:31:49:3e:30:56:73:55:fe:96:82:4e:7c:53:a8:ee:21:05:d8:f1:d5:1e:52:bb:96:5c:bf:ae:b9:cc:51:ae:9f:d3:98:af:1e:f0:3e:a9:b5:c4:c6:74:ef:f2:af:e2:07:02:f8:8f:d0:64:c7:34:93:ab:38:7e:ef
>    * shake_128: da:ee:b0:2a:3d:b5:57:05:b6:ee:8d:bd:e9:d4:20:0f:54:1e:0a:e6:39:bb:de:2d:35:a8:a3:da:86:a3:f8:a3
>    * shake_256: d6:6f:0e:34:0d:fa:bb:58:c3:db:48:ff:3c:3b:de:c6:4e:43:9f:fd:81:28:5a:01:35:5c:bf:30:85:7a:b9:ea


### openssl-certificate-complete-chain
***
Complete certificate chain given a set of untrusted and root certificates
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/certificate_complete_chain_module.html


#### Base Command

`openssl-certificate-complete-chain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| input_chain | A concatenated set of certificates in PEM format forming a chain.<br/>The module will try to complete this chain. | Required | 
| root_certificates | A list of filenames or directories.<br/>A filename is assumed to point to a file containing one or more certificates in PEM format. All certificates in this file will be added to the set of root certificates.<br/>If a directory name is given, all files in the directory and its subdirectories will be scanned and tried to be parsed as concatenated certificates in PEM format.<br/>Symbolic links will be followed. | Required | 
| intermediate_certificates | A list of filenames or directories.<br/>A filename is assumed to point to a file containing one or more certificates in PEM format. All certificates in this file will be added to the set of root certificates.<br/>If a directory name is given, all files in the directory and its subdirectories will be scanned and tried to be parsed as concatenated certificates in PEM format.<br/>Symbolic links will be followed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.certificateCompleteChain.root | string | The root certificate in PEM format. | 
| OpenSSL.certificateCompleteChain.chain | unknown | The chain added to the given input chain. Includes the root certificate.
Returned as a list of PEM certificates. | 
| OpenSSL.certificateCompleteChain.complete_chain | unknown | The completed chain, including leaf, all intermediates, and root.
Returned as a list of PEM certificates. | 




### openssl-get-certificate
***
Get a certificate from a host:port
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/get_certificate_module.html


#### Base Command

`openssl-get-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| host | The host to get the cert for (IP is fine). | Required | 
| ca_cert | A PEM file containing one or more root certificates; if present, the cert will be validated against these root certs.<br/>Note that this only validates the certificate is signed by the chain; not that the cert is valid for the host presenting it. | Optional | 
| port | The port to connect to. | Required | 
| proxy_host | Proxy host used when get a certificate. | Optional | 
| proxy_port | Proxy port used when get a certificate. Default is 8080. | Optional | 
| timeout | The timeout in seconds. Default is 10. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `pyopenssl`.<br/>If set to `pyopenssl`, will try to use the `pyOpenSSL,https://pypi.org/project/pyOpenSSL/` library.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, pyopenssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.getCertificate.cert | string | The certificate retrieved from the port | 
| OpenSSL.getCertificate.expired | boolean | Boolean indicating if the cert is expired | 
| OpenSSL.getCertificate.extensions | unknown | Extensions applied to the cert | 
| OpenSSL.getCertificate.issuer | unknown | Information about the issuer of the cert | 
| OpenSSL.getCertificate.not_after | string | Expiration date of the cert | 
| OpenSSL.getCertificate.not_before | string | Issue date of the cert | 
| OpenSSL.getCertificate.serial_number | string | The serial number of the cert | 
| OpenSSL.getCertificate.signature_algorithm | string | The algorithm used to sign the cert | 
| OpenSSL.getCertificate.subject | unknown | Information about the subject of the cert \(OU, CN, etc\) | 
| OpenSSL.getCertificate.version | string | The version number of the certificate | 

