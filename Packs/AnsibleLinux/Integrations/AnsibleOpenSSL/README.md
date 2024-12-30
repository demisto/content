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

## Configure Ansible OpenSSL in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username | The credentials to associate with the instance. SSH keys can be configured using the credential manager. | True |
| Password |  | True |
| Default SSH Port | The default port to use if one is not specified in the commands \`host\` argument. | True |
| Concurrency Factor | If multiple hosts are specified in a command, how many hosts should be interacted with concurrently. | True |
| Escalate Privileges | Ansible allows you to ‘become’ another user, different from the user that<br/>logged into the machine \(remote user\).<br/> | True |
| Privilege Escalation Method | Which privilege escalation method should be used. | True |
| Privilege Escalation User | Set the user you become through privilege escalation | False |
| Privilege Escalation Password | Set the privilege escalation password. | False |

## Testing
This integration does not support testing from the integration management screen. Instead it is recommended to use the `!openssl-certificate-info` command providing an example `host` and `path` to a certificate as the command argument. This command will connect to the specified host with the configured credentials in the integration, and if successful output information about the certificate at the path.

## Complex Command Inputs
Some commands may require structured input arguments such as `lists` or `dictionary`, these can be provided in standard JSON notation wrapped in double curly braces. For example a argument called `dns_servers` that accepts a list of server IPs 8.8.8.8 and 8.8.4.4 would be entered as `dns_servers="{{ ['8.8.8.8', '8.8.4.4'] }}"`.

Other more advanced data manipulation tools such as [Ansible](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html)/[Jinja2 filters](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters) can also be used in-line. For example to get a [random number](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html#random-number-filter) between 0 and 60 you can use `{{ 60 | random }}`.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| OpenSSL.OpensslCertificate.filename | string | Path to the generated Certificate | 
| OpenSSL.OpensslCertificate.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-certificate host="123.123.123.123" path="/etc/ssl/crt/ansible.com.crt" privatekey_path="/etc/ssl/private/ansible.com.pem" csr_path="/etc/ssl/csr/www.ansible.com.csr" provider="selfsigned" ```

#### Context Example
```json
{
    "OpenSSL": {
        "OpensslCertificate": {
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
| OpenSSL.OpensslCertificateInfo.expired | boolean | Whether the certificate is expired \(i.e. \`notAfter\` is in the past\) | 
| OpenSSL.OpensslCertificateInfo.basic_constraints | unknown | Entries in the \`basic_constraints\` extension, or \`none\` if extension is not present. | 
| OpenSSL.OpensslCertificateInfo.basic_constraints_critical | boolean | Whether the \`basic_constraints\` extension is critical. | 
| OpenSSL.OpensslCertificateInfo.extended_key_usage | unknown | Entries in the \`extended_key_usage\` extension, or \`none\` if extension is not present. | 
| OpenSSL.OpensslCertificateInfo.extended_key_usage_critical | boolean | Whether the \`extended_key_usage\` extension is critical. | 
| OpenSSL.OpensslCertificateInfo.extensions_by_oid | unknown | Returns a dictionary for every extension OID | 
| OpenSSL.OpensslCertificateInfo.key_usage | string | Entries in the \`key_usage\` extension, or \`none\` if extension is not present. | 
| OpenSSL.OpensslCertificateInfo.key_usage_critical | boolean | Whether the \`key_usage\` extension is critical. | 
| OpenSSL.OpensslCertificateInfo.subject_alt_name | unknown | Entries in the \`subject_alt_name\` extension, or \`none\` if extension is not present. | 
| OpenSSL.OpensslCertificateInfo.subject_alt_name_critical | boolean | Whether the \`subject_alt_name\` extension is critical. | 
| OpenSSL.OpensslCertificateInfo.ocsp_must_staple | boolean | \`yes\` if the OCSP Must Staple extension is present, \`none\` otherwise. | 
| OpenSSL.OpensslCertificateInfo.ocsp_must_staple_critical | boolean | Whether the \`ocsp_must_staple\` extension is critical. | 
| OpenSSL.OpensslCertificateInfo.issuer | unknown | The certificate's issuer.
Note that for repeated values, only the last one will be returned. | 
| OpenSSL.OpensslCertificateInfo.issuer_ordered | unknown | The certificate's issuer as an ordered list of tuples. | 
| OpenSSL.OpensslCertificateInfo.subject | unknown | The certificate's subject as a dictionary.
Note that for repeated values, only the last one will be returned. | 
| OpenSSL.OpensslCertificateInfo.subject_ordered | unknown | The certificate's subject as an ordered list of tuples. | 
| OpenSSL.OpensslCertificateInfo.not_after | string | \`notAfter\` date as ASN.1 TIME | 
| OpenSSL.OpensslCertificateInfo.not_before | string | \`notBefore\` date as ASN.1 TIME | 
| OpenSSL.OpensslCertificateInfo.public_key | string | Certificate's public key in PEM format | 
| OpenSSL.OpensslCertificateInfo.public_key_fingerprints | unknown | Fingerprints of certificate's public key.
For every hash algorithm available, the fingerprint is computed. | 
| OpenSSL.OpensslCertificateInfo.signature_algorithm | string | The signature algorithm used to sign the certificate. | 
| OpenSSL.OpensslCertificateInfo.serial_number | number | The certificate's serial number. | 
| OpenSSL.OpensslCertificateInfo.version | number | The certificate version. | 
| OpenSSL.OpensslCertificateInfo.valid_at | unknown | For every time stamp provided in the \`valid_at\` option, a boolean whether the certificate is valid at that point in time or not. | 
| OpenSSL.OpensslCertificateInfo.subject_key_identifier | string | The certificate's subject key identifier.
The identifier is returned in hexadecimal, with \`:\` used to separate bytes.
Is \`none\` if the \`SubjectKeyIdentifier\` extension is not present. | 
| OpenSSL.OpensslCertificateInfo.authority_key_identifier | string | The certificate's authority key identifier.
The identifier is returned in hexadecimal, with \`:\` used to separate bytes.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.OpensslCertificateInfo.authority_cert_issuer | unknown | The certificate's authority cert issuer as a list of general names.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.OpensslCertificateInfo.authority_cert_serial_number | number | The certificate's authority cert serial number.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.OpensslCertificateInfo.ocsp_uri | string | The OCSP responder URI, if included in the certificate. Will be \`none\` if no OCSP responder URI is included. | 


#### Command Example
```!openssl-certificate-info host="123.123.123.123" path="/etc/ssl/crt/ansible.com.crt"```

#### Context Example
```json
{
    "OpenSSL": {
        "OpensslCertificateInfo": {
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
                "1.1.1.1": {
                    "critical": false,
                    "value": "BBRtlXuXV61dCrNybX135iGY0y8Yxg=="
                },
                "1.1.1.2": {
                    "critical": false,
                    "value": "MBGCD3d3dy5hbnNpYmxlLmNvbQ=="
                }
            },
            "fingerprints": {
                "blake2b": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14:11:11:11:11:11:11:11:15:11:11:11:11:11:11:11:16:11:11:11:11:11:11:11:17:11:11:11:11:11:11:11:18",
                "blake2s": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "md5": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha1": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_128": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14"
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
                "blake2b": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "blake2s": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "md5": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha1": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_128": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14"
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
            "subject_key_identifier": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
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
>  * subject_key_identifier: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>  * version: 3
>  * ## Extensions_By_Oid
>    * ### 1.1.1.1
>      * critical: False
>      * value: BBRtlXuXV61dCrNybX135iGY0y8Yxg==
>    * ### 1.1.1.2
>      * critical: False
>      * value: MBGCD3d3dy5hbnNpYmxlLmNvbQ==
>  * ## Fingerprints
>    * blake2b: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14:11:11:11:11:11:11:11:15:11:11:11:11:11:11:11:16:11:11:11:11:11:11:11:17:11:11:11:11:11:11:11:18
>    * blake2s: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * md5: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha1: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_128: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>  * ## Issuer
>    * commonName: www.ansible.com
>  * ## Issuer_Ordered
>  * ## List
>    * 0: commonName
>    * 1: www.ansible.com
>  * ## Public_Key_Fingerprints
>    * blake2b: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * blake2s: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * md5: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha1: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_128: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
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
| OpenSSL.OpensslCsr.privatekey | string | Path to the TLS/SSL private key the CSR was generated for | 
| OpenSSL.OpensslCsr.filename | string | Path to the generated Certificate Signing Request | 
| OpenSSL.OpensslCsr.subject | unknown | A list of the subject tuples attached to the CSR | 
| OpenSSL.OpensslCsr.subjectAltName | unknown | The alternative names this CSR is valid for | 
| OpenSSL.OpensslCsr.keyUsage | unknown | Purpose for which the public key may be used | 
| OpenSSL.OpensslCsr.extendedKeyUsage | unknown | Additional restriction on the public key purposes | 
| OpenSSL.OpensslCsr.basicConstraints | unknown | Indicates if the certificate belongs to a CA | 
| OpenSSL.OpensslCsr.ocsp_must_staple | boolean | Indicates whether the certificate has the OCSP Must Staple feature enabled | 
| OpenSSL.OpensslCsr.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-csr host="123.123.123.123" path="/etc/ssl/csr/www.ansible.com.csr" privatekey_path="/etc/ssl/private/ansible.com.pem" common_name="www.ansible.com" ```

#### Context Example
```json
{
    "OpenSSL": {
        "OpensslCsr": {
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
| OpenSSL.OpensslCsrInfo.signature_valid | boolean | Whether the CSR's signature is valid.
In case the check returns \`no\`, the module will fail. | 
| OpenSSL.OpensslCsrInfo.basic_constraints | unknown | Entries in the \`basic_constraints\` extension, or \`none\` if extension is not present. | 
| OpenSSL.OpensslCsrInfo.basic_constraints_critical | boolean | Whether the \`basic_constraints\` extension is critical. | 
| OpenSSL.OpensslCsrInfo.extended_key_usage | unknown | Entries in the \`extended_key_usage\` extension, or \`none\` if extension is not present. | 
| OpenSSL.OpensslCsrInfo.extended_key_usage_critical | boolean | Whether the \`extended_key_usage\` extension is critical. | 
| OpenSSL.OpensslCsrInfo.extensions_by_oid | unknown | Returns a dictionary for every extension OID | 
| OpenSSL.OpensslCsrInfo.key_usage | string | Entries in the \`key_usage\` extension, or \`none\` if extension is not present. | 
| OpenSSL.OpensslCsrInfo.key_usage_critical | boolean | Whether the \`key_usage\` extension is critical. | 
| OpenSSL.OpensslCsrInfo.subject_alt_name | unknown | Entries in the \`subject_alt_name\` extension, or \`none\` if extension is not present. | 
| OpenSSL.OpensslCsrInfo.subject_alt_name_critical | boolean | Whether the \`subject_alt_name\` extension is critical. | 
| OpenSSL.OpensslCsrInfo.ocsp_must_staple | boolean | \`yes\` if the OCSP Must Staple extension is present, \`none\` otherwise. | 
| OpenSSL.OpensslCsrInfo.ocsp_must_staple_critical | boolean | Whether the \`ocsp_must_staple\` extension is critical. | 
| OpenSSL.OpensslCsrInfo.subject | unknown | The CSR's subject as a dictionary.
Note that for repeated values, only the last one will be returned. | 
| OpenSSL.OpensslCsrInfo.subject_ordered | unknown | The CSR's subject as an ordered list of tuples. | 
| OpenSSL.OpensslCsrInfo.public_key | string | CSR's public key in PEM format | 
| OpenSSL.OpensslCsrInfo.public_key_fingerprints | unknown | Fingerprints of CSR's public key.
For every hash algorithm available, the fingerprint is computed. | 
| OpenSSL.OpensslCsrInfo.subject_key_identifier | string | The CSR's subject key identifier.
The identifier is returned in hexadecimal, with \`:\` used to separate bytes.
Is \`none\` if the \`SubjectKeyIdentifier\` extension is not present. | 
| OpenSSL.OpensslCsrInfo.authority_key_identifier | string | The CSR's authority key identifier.
The identifier is returned in hexadecimal, with \`:\` used to separate bytes.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.OpensslCsrInfo.authority_cert_issuer | unknown | The CSR's authority cert issuer as a list of general names.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 
| OpenSSL.OpensslCsrInfo.authority_cert_serial_number | number | The CSR's authority cert serial number.
Is \`none\` if the \`AuthorityKeyIdentifier\` extension is not present. | 


#### Command Example
```!openssl-csr-info host="123.123.123.123" path="/etc/ssl/csr/www.ansible.com.csr"```

#### Context Example
```json
{
    "OpenSSL": {
        "OpensslCsrInfo": {
            "authority_cert_issuer": null,
            "authority_cert_serial_number": null,
            "authority_key_identifier": null,
            "basic_constraints": null,
            "basic_constraints_critical": false,
            "changed": false,
            "extended_key_usage": null,
            "extended_key_usage_critical": false,
            "extensions_by_oid": {
                "1.1.1.2": {
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
                "blake2b": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "blake2s": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "md5": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha1": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_128": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14"
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
>    * ### 1.1.1.2
>      * critical: False
>      * value: MBGCD3d3dy5hbnNpYmxlLmNvbQ==
>  * ## Public_Key_Fingerprints
>    * blake2b: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * blake2s: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * md5: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha1: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_128: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
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
| OpenSSL.OpensslDhparam.size | number | Size \(in bits\) of the Diffie-Hellman parameters. | 
| OpenSSL.OpensslDhparam.filename | string | Path to the generated Diffie-Hellman parameters. | 
| OpenSSL.OpensslDhparam.backup_file | string | Name of backup file created. | 




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
| OpenSSL.OpensslPkcs12.filename | string | Path to the generate PKCS\#12 file. | 
| OpenSSL.OpensslPkcs12.privatekey | string | Path to the TLS/SSL private key the public key was generated from. | 
| OpenSSL.OpensslPkcs12.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-pkcs12 host="123.123.123.123" action="export" path="/opt/certs/ansible.p12" friendly_name="raclette" privatekey_path="/etc/ssl/private/ansible.com.pem" certificate_path="/etc/ssl/crt/ansible.com.crt" other_certificates="/etc/ssl/crt/ca.crt" state="present" ```

#### Context Example
```json
{
    "OpenSSL": {
        "OpensslPkcs12": {
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
| OpenSSL.OpensslPrivatekey.size | number | Size \(in bits\) of the TLS/SSL private key. | 
| OpenSSL.OpensslPrivatekey.type | string | Algorithm used to generate the TLS/SSL private key. | 
| OpenSSL.OpensslPrivatekey.curve | string | Elliptic curve used to generate the TLS/SSL private key. | 
| OpenSSL.OpensslPrivatekey.filename | string | Path to the generated TLS/SSL private key file. | 
| OpenSSL.OpensslPrivatekey.fingerprint | unknown | The fingerprint of the public key. Fingerprint will be generated for each \`hashlib.algorithms\` available.
The PyOpenSSL backend requires PyOpenSSL &gt;= 16.0 for meaningful output. | 
| OpenSSL.OpensslPrivatekey.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-privatekey host="123.123.123.123" path="/etc/ssl/private/ansible.com.pem" ```

#### Context Example
```json
{
    "OpenSSL": {
        "OpensslPrivatekey": {
            "changed": false,
            "filename": "/etc/ssl/private/ansible.com.pem",
            "fingerprint": {
                "blake2b": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "blake2s": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "md5": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha1": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_128": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14"
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
>    * blake2b: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * blake2s: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * md5: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha1: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_128: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14


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
| OpenSSL.OpensslPrivatekeyInfo.can_load_key | boolean | Whether the module was able to load the private key from disk | 
| OpenSSL.OpensslPrivatekeyInfo.can_parse_key | boolean | Whether the module was able to parse the private key | 
| OpenSSL.OpensslPrivatekeyInfo.key_is_consistent | boolean | Whether the key is consistent. Can also return \`none\` next to \`yes\` and \`no\`, to indicate that consistency couldn't be checked.
In case the check returns \`no\`, the module will fail. | 
| OpenSSL.OpensslPrivatekeyInfo.public_key | string | Private key's public key in PEM format | 
| OpenSSL.OpensslPrivatekeyInfo.public_key_fingerprints | unknown | Fingerprints of private key's public key.
For every hash algorithm available, the fingerprint is computed. | 
| OpenSSL.OpensslPrivatekeyInfo.type | string | The key's type.
One of \`RSA\`, \`DSA\`, \`ECC\`, \`Ed25519\`, \`X25519\`, \`Ed448\`, or \`X448\`.
Will start with \`unknown\` if the key type cannot be determined. | 
| OpenSSL.OpensslPrivatekeyInfo.public_data | unknown | Public key data. Depends on key type. | 
| OpenSSL.OpensslPrivatekeyInfo.private_data | unknown | Private key data. Depends on key type. | 


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
| OpenSSL.OpensslPublickey.privatekey | string | Path to the TLS/SSL private key the public key was generated from. | 
| OpenSSL.OpensslPublickey.format | string | The format of the public key \(PEM, OpenSSH, ...\). | 
| OpenSSL.OpensslPublickey.filename | string | Path to the generated TLS/SSL public key file. | 
| OpenSSL.OpensslPublickey.fingerprint | unknown | The fingerprint of the public key. Fingerprint will be generated for each hashlib.algorithms available.
Requires PyOpenSSL &gt;= 16.0 for meaningful output. | 
| OpenSSL.OpensslPublickey.backup_file | string | Name of backup file created. | 


#### Command Example
```!openssl-publickey host="123.123.123.123" path="/etc/ssl/public/ansible.com.pem" privatekey_path="/etc/ssl/private/ansible.com.pem" ```

#### Context Example
```json
{
    "OpenSSL": {
        "OpensslPublickey": {
            "changed": false,
            "filename": "/etc/ssl/public/ansible.com.pem",
            "fingerprint": {
                "blake2b": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "blake2s": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "md5": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha1": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_224": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_384": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha3_512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "sha512": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_128": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14",
                "shake_256": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14"
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
>    * blake2b: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * blake2s: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * md5: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha1: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_224: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_384: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha3_512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * sha512: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_128: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14
>    * shake_256: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:13:11:11:11:11:11:11:11:14


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
| OpenSSL.CertificateCompleteChain.root | string | The root certificate in PEM format. | 
| OpenSSL.CertificateCompleteChain.chain | unknown | The chain added to the given input chain. Includes the root certificate.
Returned as a list of PEM certificates. | 
| OpenSSL.CertificateCompleteChain.complete_chain | unknown | The completed chain, including leaf, all intermediates, and root.
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
| ansible-module-host | The host to get the cert for (IP is fine). | Required | 
| ca_cert | A PEM file containing one or more root certificates; if present, the cert will be validated against these root certs.<br/>Note that this only validates the certificate is signed by the chain; not that the cert is valid for the host presenting it. | Optional | 
| port | The port to connect to. | Required | 
| proxy_host | Proxy host used when get a certificate. | Optional | 
| proxy_port | Proxy port used when get a certificate. Default is 8080. | Optional | 
| timeout | The timeout in seconds. Default is 10. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `pyopenssl`.<br/>If set to `pyopenssl`, will try to use the `pyOpenSSL,https://pypi.org/project/pyOpenSSL/` library.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, pyopenssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenSSL.GetCertificate.cert | string | The certificate retrieved from the port | 
| OpenSSL.GetCertificate.expired | boolean | Boolean indicating if the cert is expired | 
| OpenSSL.GetCertificate.extensions | unknown | Extensions applied to the cert | 
| OpenSSL.GetCertificate.issuer | unknown | Information about the issuer of the cert | 
| OpenSSL.GetCertificate.not_after | string | Expiration date of the cert | 
| OpenSSL.GetCertificate.not_before | string | Issue date of the cert | 
| OpenSSL.GetCertificate.serial_number | string | The serial number of the cert | 
| OpenSSL.GetCertificate.signature_algorithm | string | The algorithm used to sign the cert | 
| OpenSSL.GetCertificate.subject | unknown | Information about the subject of the cert \(OU, CN, etc\) | 
| OpenSSL.GetCertificate.version | string | The version number of the certificate | 


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
