Automatic Certificate Management Environment on Linux hosts management.
This integration lets you manage certificate generation on Linux hosts with a CA supporting the ACME protocol, such as Let’s Encrypt.

This integration was tested with Let's Encrypt and supports the ACME http-01, dns-01 and tls-alpn-01 challenges.

## Requirements
This integration requires a linux host to be specified from which the connections to the ACME service will be performed, and where the certificate/key files will be stored.

The Linux host used for ACME interaction requires:
* python >= 2.6
* either openssl or cryptography >= 1.5

## Network Requirements
By default, TCP port 22 will be used to initiate a SSH connection to the Linux host.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.
## Credentials
This integration supports a number of methods of authenticating with the Linux Host:
1. Username & Password entered into the integration
2. Username & Password credential from the XSOAR credential manager
3. Username and SSH Key from the XSOAR credential manager

## Permissions
Normal Linux user privileges are required, a SuperUser account is not required.
ACME Account management operations require access to the ACME account RSA or Elliptic Curve key file on the Linux host used for management to authenticate with the ACME service.

## Further information
This integration is powered by Ansible 2.9. Further information can be found on that the following locations:
* [The Let’s Encrypt documentation](https://letsencrypt.org/docs/)
* [Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/rfc8555)

## Configure ACME on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ACME.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Username | The credentials to associate with the instance. SSH keys can be configured using the credential manager. | True |
    | Default SSH Port | The default port to use if one is not specified in the commands \`host\` argument. | True |
    | Concurrency Factor | If multiple hosts are specified in a command, how many hosts should be interacted with concurrently. | True |
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### acme-account
***
Create, modify or delete ACME accounts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/acme_account_module.html


#### Base Command

`acme-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | The state of the account, to be identified by its account key.<br/>If the state is `absent`, the account will either not exist or be deactivated.<br/>If the state is `changed_key`, the account must exist. The account key will be changed; no other information will be touched. Possible values are: present, absent, changed_key. | Required | 
| allow_creation | Whether account creation is allowed (when state is `present`). Default is True. | Optional | 
| contact | A list of contact URLs.<br/>Email addresses must be prefixed with `mailto:`.<br/>See `https://tools.ietf.org/html/rfc8555#section-7.3` for what is allowed.<br/>Must be specified when state is `present`. Will be ignored if state is `absent` or `changed_key`. Default is []. | Optional | 
| terms_agreed | Boolean indicating whether you agree to the terms of service document.<br/>ACME servers can require this to be true. Default is False. | Optional | 
| new_account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key to change to.<br/>Same restrictions apply as to `account_key_src`.<br/>Mutually exclusive with `new_account_key_content`.<br/>Required if `new_account_key_content` is not used and state is `changed_key`. | Optional | 
| new_account_key_content | Content of the ACME account RSA or Elliptic Curve key to change to.<br/>Same restrictions apply as to `account_key_content`.<br/>Mutually exclusive with `new_account_key_src`.<br/>Required if `new_account_key_src` is not used and state is `changed_key`. | Optional | 
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key.<br/>RSA keys can be created with `openssl genrsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well.<br/>Mutually exclusive with `account_key_content`.<br/>Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Mutually exclusive with `account_key_src`.<br/>Required if `account_key_src` is not used.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint.<br/>Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API.<br/>For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates.<br/>For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints`<br/>For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`.<br/>For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`.<br/>`Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates.<br/>`Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Default is True. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`.<br/>If set to `openssl`, will try to use the `openssl` binary.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.acme_account.account_uri | string | ACME account URI, or None if account does not exist. | 


#### Command Example
```!acme-account host="123.123.123.123" account_key_src="/etc/letsencrypt/keys/example.com.key" state="present" terms_agreed="True" contact="mailto:user@example.com"  acme_version=2 acme_directory=https://acme-staging-v02.api.letsencrypt.org/directory```

#### Context Example
```json
{
    "acme": {
        "acme_account": [
            {
                "account_uri": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345678",
                "changed": false,
                "host": "123.123.123.123",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * account_uri: https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345678
>  * changed: False


### acme-account-info
***
Retrieves information on ACME accounts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/acme_account_info_module.html


#### Base Command

`acme-account-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| retrieve_orders | Whether to retrieve the list of order URLs or order objects, if provided by the ACME server.<br/>A value of `ignore` will not fetch the list of orders.<br/>Currently, Let's Encrypt does not return orders, so the `orders` result will always be empty. Possible values are: ignore, url_list, object_list. Default is ignore. | Optional | 
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key.<br/>RSA keys can be created with `openssl genrsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well.<br/>Mutually exclusive with `account_key_content`.<br/>Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Mutually exclusive with `account_key_src`.<br/>Required if `account_key_src` is not used.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint.<br/>Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API.<br/>For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates.<br/>For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints`<br/>For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`.<br/>For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`.<br/>`Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates.<br/>`Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Default is True. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`.<br/>If set to `openssl`, will try to use the `openssl` binary.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.acme_account_info.exists | boolean | Whether the account exists. | 
| ACME.acme_account_info.account_uri | string | ACME account URI, or None if account does not exist. | 
| ACME.acme_account_info.account | unknown | The account information, as retrieved from the ACME server. | 
| ACME.acme_account_info.orders | unknown | 
The list of orders.
If \`retrieve_orders\` is \`url_list\`, this will be a list of URLs.
If \`retrieve_orders\` is \`object_list\`, this will be a list of objects. | 


#### Command Example
```!acme-account-info host="123.123.123.123" account_key_src="/etc/letsencrypt/keys/example.com.key" acme_version=2 acme_directory=https://acme-staging-v02.api.letsencrypt.org/directory```

#### Context Example
```json
{
    "acme": {
        "acme_account_info": [
            {
                "account": {
                    "contact": [
                        "mailto:user@example.com"
                    ],
                    "createdAt": "2021-05-24T13:51:42Z",
                    "initialIp": "321.321.321.321",
                    "key": {
                        "e": "AQAB",
                        "kty": "RSA",
                        "n": "8unmQBuNgfDtLdmReMoZ_cvijRG-7KyVR...REDACTED...98bI2lpba9hwG7omPtG3ey7MnMZpXcs6ybYsnzhoZnWNpxDCs-rRY-MPk7U"
                    },
                    "public_account_key": {
                        "e": "AQAB",
                        "kty": "RSA",
                        "n": "8unmQBuNgfDtLdmReMoZ_cvijRG-7KyVR...REDACTED...98bI2lpba9hwG7omPtG3ey7MnMZpXcs6ybYsnzhoZnWNpxDCs-rRY-MPk7U"
                    },
                    "status": "valid"
                },
                "account_uri": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345678",
                "changed": false,
                "exists": true,
                "host": "123.123.123.123",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
># Account #
>* ## Contact ##
>  * 0: mailto:user@example.com
>* createdAt: 2021-05-24T13:51:42Z
>* initialIp: 321.321.321.321
>* ## Key ##
>  * e: AQAB
>  * kty: RSA
>  * n: 8unmQBuNgfDtLdmReMoZ_cvijRG-7KyVR...REDACTED...98bI2lpba9hwG7omPtG3ey7MnMZpXcs6ybYsnzhoZnWNpxDCs-rRY-MPk7U
>* ## Public_Account_Key ##
>  * e: AQAB
>  * kty: RSA
>  * n: 8unmQBuNgfDtLdmReMoZ_cvijRG-7KyVR...REDACTED...98bI2lpba9hwG7omPtG3ey7MnMZpXcs6ybYsnzhoZnWNpxDCs-rRY-MPk7U
>* status: valid
>  * account_uri: https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345678
>  * changed: False
>  * exists: True


### acme-certificate
***
Create SSL/TLS certificates with the ACME protocol
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/acme_certificate_module.html


#### Base Command

`acme-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| account_email | The email address associated with this account.<br/>It will be used for certificate expiration warnings.<br/>Note that when `modify_account` is not set to `no` and you also used the `acme_account` module to specify more than one contact for your account, this module will update your account and restrict it to the (at most one) contact email address specified here. | Optional | 
| agreement | URI to a terms of service document you agree to when using the ACME v1 service at `acme_directory`.<br/>Default is latest gathered from `acme_directory` URL.<br/>This option will only be used when `acme_version` is 1. | Optional | 
| terms_agreed | Boolean indicating whether you agree to the terms of service document.<br/>ACME servers can require this to be true.<br/>This option will only be used when `acme_version` is not 1. Default is False. | Optional | 
| modify_account | Boolean indicating whether the module should create the account if necessary, and update its contact data.<br/>Set to `no` if you want to use the `acme_account` module to manage your account instead, and to avoid accidental creation of a new account using an old key if you changed the account key with `acme_account`.<br/>If set to `no`, `terms_agreed` and `account_email` are ignored. Default is True. | Optional | 
| challenge | The challenge to be performed. Possible values are: http-01, dns-01, tls-alpn-01. Default is http-01. | Optional | 
| csr | File containing the CSR for the new certificate.<br/>Can be created with `openssl req ...`.<br/>The CSR may contain multiple Subject Alternate Names, but each one will lead to an individual challenge that must be fulfilled for the CSR to be signed.<br/>`Note`: the private key used to create the CSR `must not` be the account key. This is a bad idea from a security point of view, and the CA should not accept the CSR. The ACME server should return an error in this case. | Required | 
| data | The data to validate ongoing challenges. This must be specified for the second run of the module only.<br/>The value that must be used here will be provided by a previous use of this module. See the examples for more details.<br/>Note that for ACME v2, only the `order_uri` entry of `data` will be used. For ACME v1, `data` must be non-empty to indicate the second stage is active; all needed data will be taken from the CSR.<br/>`Note`: the `data` option was marked as `no_log` up to Ansible 2.5. From Ansible 2.6 on, it is no longer marked this way as it causes error messages to be come unusable, and `data` does not contain any information which can be used without having access to the account key or which are not public anyway. | Optional | 
| dest | The destination file for the certificate.<br/>Required if `fullchain_dest` is not specified. | Optional | 
| fullchain_dest | The destination file for the full chain (i.e. certificate followed by chain of intermediate certificates).<br/>Required if `dest` is not specified. | Optional | 
| chain_dest | If specified, the intermediate certificate will be written to this file. | Optional | 
| remaining_days | The number of days the certificate must have left being valid. If `cert_days &lt; remaining_days`, then it will be renewed. If the certificate is not renewed, module return values will not include `challenge_data`.<br/>To make sure that the certificate is renewed in any case, you can use the `force` option. Default is 10. | Optional | 
| deactivate_authzs | Deactivate authentication objects (authz) after issuing a certificate, or when issuing the certificate failed.<br/>Authentication objects are bound to an account key and remain valid for a certain amount of time, and can be used to issue certificates without having to re-authenticate the domain. This can be a security concern. Default is False. | Optional | 
| force | Enforces the execution of the challenge and validation, even if an existing certificate is still valid for more than `remaining_days`.<br/>This is especially helpful when having an updated CSR e.g. with additional domains for which a new certificate is desired. Default is False. | Optional | 
| retrieve_all_alternates | When set to `yes`, will retrieve all alternate chains offered by the ACME CA. These will not be written to disk, but will be returned together with the main chain as `all_chains`. See the documentation for the `all_chains` return value for details. Default is False. | Optional | 
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key.<br/>RSA keys can be created with `openssl genrsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well.<br/>Mutually exclusive with `account_key_content`.<br/>Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Mutually exclusive with `account_key_src`.<br/>Required if `account_key_src` is not used.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint.<br/>Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API.<br/>For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates.<br/>For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints`<br/>For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`.<br/>For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`.<br/>`Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates.<br/>`Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Default is True. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`.<br/>If set to `openssl`, will try to use the `openssl` binary.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.acme_certificate.cert_days | number | The number of days the certificate remains valid. | 
| ACME.acme_certificate.challenge_data | unknown | 
Per identifier / challenge type challenge data.
Since Ansible 2.8.5, only challenges which are not yet valid are returned. | 
| ACME.acme_certificate.challenge_data_dns | unknown | 
List of TXT values per DNS record, in case challenge is \`dns-01\`.
Since Ansible 2.8.5, only challenges which are not yet valid are returned. | 
| ACME.acme_certificate.authorizations | unknown | 
ACME authorization data.
Maps an identifier to ACME authorization objects. See \`https://tools.ietf.org/html/rfc8555\#section-7.1.4\`. | 
| ACME.acme_certificate.order_uri | string | ACME order URI. | 
| ACME.acme_certificate.finalization_uri | string | ACME finalization URI. | 
| ACME.acme_certificate.account_uri | string | ACME account URI. | 
| ACME.acme_certificate.all_chains | unknown | 
When \`retrieve_all_alternates\` is set to \`yes\`, the module will query the ACME server for alternate chains. This return value will contain a list of all chains returned, the first entry being the main chain returned by the server.
See \`Section 7.4.2 of RFC8555,https://tools.ietf.org/html/rfc8555\#section-7.4.2\` for details. | 


#### Command Example
```!acme-certificate host="123.123.123.123" account_key_src="/etc/letsencrypt/keys/example.com.key" dest=/etc/letsencrypt/certs/test.example.com.crt csr=/etc/letsencrypt/csrs/example.com.csr acme_directory=https://acme-v02.api.letsencrypt.org/directory acme_version=2 challenge="dns-01" terms_agreed=1```

#### Context Example
```json
{
    "acme": {
        "acme_certificate": [
            {
                "cert_days": 89,
                "changed": false,
                "host": "123.123.123.123",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * cert_days: 89
>  * changed: False


### acme-certificate-revoke
***
Revoke certificates with the ACME protocol
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/acme_certificate_revoke_module.html


#### Base Command

`acme-certificate-revoke`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| certificate | Path to the certificate to revoke. | Required | 
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key.<br/>RSA keys can be created with `openssl rsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well.<br/>Mutually exclusive with `account_key_content`.<br/>Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Note that exactly one of `account_key_src`, `account_key_content`, `private_key_src` or `private_key_content` must be specified.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| private_key_src | Path to the certificate's private key.<br/>Note that exactly one of `account_key_src`, `account_key_content`, `private_key_src` or `private_key_content` must be specified. | Optional | 
| private_key_content | Content of the certificate's private key.<br/>Note that exactly one of `account_key_src`, `account_key_content`, `private_key_src` or `private_key_content` must be specified.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| revoke_reason | One of the revocation reasonCodes defined in `Section 5.3.1 of RFC5280,https://tools.ietf.org/html/rfc5280#section-5.3.1`.<br/>Possible values are `0` (unspecified), `1` (keyCompromise), `2` (cACompromise), `3` (affiliationChanged), `4` (superseded), `5` (cessationOfOperation), `6` (certificateHold), `8` (removeFromCRL), `9` (privilegeWithdrawn), `10` (aACompromise). | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint.<br/>Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API.<br/>For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates.<br/>For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints`<br/>For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`.<br/>For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`.<br/>`Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates.<br/>`Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Default is True. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`.<br/>If set to `openssl`, will try to use the `openssl` binary.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### acme-challenge-cert-helper
***
Prepare certificates required for ACME challenges such as tls-alpn-01
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/acme_challenge_cert_helper_module.html


#### Base Command

`acme-challenge-cert-helper`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| challenge | The challenge type. Possible values are: tls-alpn-01. | Required | 
| challenge_data | The `challenge_data` entry provided by `acme_certificate` for the challenge. | Required | 
| private_key_src | Path to a file containing the private key file to use for this challenge certificate.<br/>Mutually exclusive with `private_key_content`. | Optional | 
| private_key_content | Content of the private key to use for this challenge certificate.<br/>Mutually exclusive with `private_key_src`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.acme_challenge_cert_helper.domain | string | 
The domain the challenge is for. The certificate should be provided if this is specified in the request's the \`Host\` header. | 
| ACME.acme_challenge_cert_helper.identifier_type | string | 
The identifier type for the actual resource identifier. Will be \`dns\` or \`ip\`. | 
| ACME.acme_challenge_cert_helper.identifier | string | 
The identifier for the actual resource. Will be a domain name if the type is \`dns\`, or an IP address if the type is \`ip\`. | 
| ACME.acme_challenge_cert_helper.challenge_certificate | string | 
The challenge certificate in PEM format. | 
| ACME.acme_challenge_cert_helper.regular_certificate | string | 
A self-signed certificate for the challenge domain.
If no existing certificate exists, can be used to set-up https in the first place if that is needed for providing the challenge. | 


#### Command Example
``` ```

#### Human Readable Output



### acme-inspect
***
Send direct requests to an ACME server
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/acme_inspect_module.html


#### Base Command

`acme-inspect`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| url | The URL to send the request to.<br/>Must be specified if `method` is not `directory-only`. | Optional | 
| method | The method to use to access the given URL on the ACME server.<br/>The value `post` executes an authenticated POST request. The content must be specified in the `content` option.<br/>The value `get` executes an authenticated POST-as-GET request for ACME v2, and a regular GET request for ACME v1.<br/>The value `directory-only` only retrieves the directory, without doing a request. Possible values are: get, post, directory-only. Default is get. | Optional | 
| content | An encoded JSON object which will be sent as the content if `method` is `post`.<br/>Required when `method` is `post`, and not allowed otherwise. | Optional | 
| fail_on_acme_error | If `method` is `post` or `get`, make the module fail in case an ACME error is returned. Default is True. | Optional | 
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key.<br/>RSA keys can be created with `openssl genrsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well.<br/>Mutually exclusive with `account_key_content`.<br/>Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Mutually exclusive with `account_key_src`.<br/>Required if `account_key_src` is not used.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint.<br/>Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API.<br/>For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates.<br/>For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints`<br/>For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`.<br/>For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`.<br/>`Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates.<br/>`Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Default is True. | Optional | 
| select_crypto_backend | Determines which crypto backend to use.<br/>The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`.<br/>If set to `openssl`, will try to use the `openssl` binary.<br/>If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.acme_inspect.directory | unknown | The ACME directory's content | 
| ACME.acme_inspect.headers | unknown | The request's HTTP headers \(with lowercase keys\) | 
| ACME.acme_inspect.output_text | string | The raw text output | 
| ACME.acme_inspect.output_json | unknown | The output parsed as JSON | 


#### Command Example
```!acme-inspect host="123.123.123.123" acme_directory="https://acme-staging-v02.api.letsencrypt.org/directory" acme_version="2" method="directory-only" ```

#### Context Example
```json
{
    "acme": {
        "acme_inspect": [
            {
                "changed": false,
                "directory": {
                    "-Wc-iaBVqrk": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
                    "keyChange": "https://acme-staging-v02.api.letsencrypt.org/acme/key-change",
                    "meta": {
                        "caaIdentities": [
                            "letsencrypt.org"
                        ],
                        "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
                        "website": "https://letsencrypt.org/docs/staging-environment/"
                    },
                    "newAccount": "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct",
                    "newNonce": "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce",
                    "newOrder": "https://acme-staging-v02.api.letsencrypt.org/acme/new-order",
                    "revokeCert": "https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert"
                },
                "host": "123.123.123.123",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
># Directory #
>* -Wc-iaBVqrk: https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417
>* keyChange: https://acme-staging-v02.api.letsencrypt.org/acme/key-change
>* ## Meta ##
>* ### Caaidentities ###
>  * 0: letsencrypt.org
>  * termsOfService: https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf
>  * website: https://letsencrypt.org/docs/staging-environment/
>* newAccount: https://acme-staging-v02.api.letsencrypt.org/acme/new-acct
>* newNonce: https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce
>* newOrder: https://acme-staging-v02.api.letsencrypt.org/acme/new-order
>* revokeCert: https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert

