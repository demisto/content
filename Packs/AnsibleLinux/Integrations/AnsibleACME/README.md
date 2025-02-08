Automatic Certificate Management Environment on Linux hosts management using Ansible modules.
This integration lets you manage certificate generation on Linux hosts with a CA supporting the ACME protocol, such as Let’s Encrypt.
The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands. This integration functions without any agents or additional software installed on the hosts by utilising SSH combined with Python.

To use this integration, configure an instance of this integration. This will associate a credential to be used to access hosts when commands are run. The commands from this integration will take the Linux host address(es) as an input, and use the saved credential associated to the instance to execute. Create separate instances if multiple credentials are required.

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

## Privilege Escalation
Ansible can use existing privilege escalation systems to allow a user to execute tasks as another. Different from the user that logged into the machine (remote user). This is done using existing privilege escalation tools, which you probably already use or have configured, like sudo, su, or doas. Use the Integration parameters `Escalate Privileges`, `Privilege Escalation Method`, `Privilege Escalation User`, `Privileges Escalation Password` to configure this.

## Further information
This integration is powered by Ansible 2.9. Further information can be found on that the following locations:
* [The Let’s Encrypt documentation](https://letsencrypt.org/docs/)
* [Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/rfc8555)
## Configure Ansible ACME in Cortex

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
This integration does not support testing from the integration management screen. Instead it is recommended to use the `!acme-inspect`command providing an example `host` as the command argument to connect to a ACME provider like Let's Encrypt. Eg. `!acme-inspect host="123.123.123.123" acme_directory="https://acme-staging-v02.api.letsencrypt.org/directory" acme_version="2" method="directory-only" ` This command will connect to the specified host with the configured credentials in the integration, and if successful output information about the Let's Encrypt ACME directory.

## Idempotence
The action commands in this integration are idempotent. This means that the result of performing it once is exactly the same as the result of performing it repeatedly without any intervening actions.

## State Arguement
Some of the commands in this integration take a state argument. These define the desired end state of the object being managed. As a result these commands are able to perform multiple management operations depending on the desired state value. Common state values are:
| **State** | **Result** |
| --- | --- |
| present | Object should exist. If not present, the object will be created with the provided parameters. If present but not with correct parameters, it will be modified to met provided parameters. |
| running | Object should be running not stopped. |
| stopped | Object should be stopped not running. |
| restarted | Object will be restarted. |
| absent | Object should not exist. If it it exists it will be deleted. |

## Complex Command Inputs
Some commands may require structured input arguments such as `lists` or `dictionary`, these can be provided in standard JSON notation wrapped in double curly braces. For example a argument called `dns_servers` that accepts a list of server IPs 8.8.8.8 and 8.8.4.4 would be entered as `dns_servers="{{ ['8.8.8.8', '8.8.4.4'] }}"`.

Other more advanced data manipulation tools such as [Ansible](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html)/[Jinja2 filters](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters) can also be used in-line. For example to get a [random number](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html#random-number-filter) between 0 and 60 you can use `{{ 60 | random }}`.
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| state | The state of the account, to be identified by its account key. If the state is `absent`, the account will either not exist or be deactivated. If the state is `changed_key`, the account must exist. The account key will be changed; no other information will be touched. Possible values are: present, absent, changed_key. | Required | 
| allow_creation | Whether account creation is allowed (when state is `present`). Possible values are: Yes, No. Default is Yes. | Optional | 
| contact | A list of contact URLs. Email addresses must be prefixed with `mailto:`. See `https://tools.ietf.org/html/rfc8555#section-7.3` for what is allowed. Must be specified when state is `present`. Will be ignored if state is `absent` or `changed_key`. | Optional | 
| terms_agreed | Boolean indicating whether you agree to the terms of service document. ACME servers can require this to be true. Possible values are: Yes, No. Default is No. | Optional | 
| new_account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key to change to. Same restrictions apply as to `account_key_src`. Mutually exclusive with `new_account_key_content`. Required if `new_account_key_content` is not used and state is `changed_key`. | Optional | 
| new_account_key_content | Content of the ACME account RSA or Elliptic Curve key to change to. Same restrictions apply as to `account_key_content`. Mutually exclusive with `new_account_key_src`. Required if `new_account_key_src` is not used and state is `changed_key`. | Optional | 
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key. RSA keys can be created with `openssl genrsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well. Mutually exclusive with `account_key_content`. Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Mutually exclusive with `account_key_src`.<br/>Required if `account_key_src` is not used.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint. Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API. For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates. For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints` For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`. For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`. `Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates. `Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Possible values are: Yes, No. Default is Yes. | Optional | 
| select_crypto_backend | Determines which crypto backend to use. The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`. If set to `openssl`, will try to use the `openssl` binary. If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.AcmeAccount.account_uri | string | ACME account URI, or None if account does not exist. | 


#### Command Example
```!acme-account host="123.123.123.123" "account_key_src"="/etc/letsencrypt/keys/example.com.key" state="present" terms_agreed="True" contact="mailto:user@example.com" acme_version=2 acme_directory=https://acme-staging-v02.api.letsencrypt.org/directory```

#### Context Example
```json
{
    "ACME": {
        "AcmeAccount": {
            "account_uri": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345678",
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
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
| retrieve_orders | Whether to retrieve the list of order URLs or order objects, if provided by the ACME server. A value of `ignore` will not fetch the list of orders. Currently, Let's Encrypt does not return orders, so the `orders` result will always be empty. Possible values are: ignore, url_list, object_list. Default is ignore. | Optional | 
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key. RSA keys can be created with `openssl genrsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well. Mutually exclusive with `account_key_content`. Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Mutually exclusive with `account_key_src`.<br/>Required if `account_key_src` is not used.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint. Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API. For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates. For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints` For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`. For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`. `Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates. `Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Possible values are: Yes, No. Default is Yes. | Optional | 
| select_crypto_backend | Determines which crypto backend to use. The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`. If set to `openssl`, will try to use the `openssl` binary. If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.AcmeAccountInfo.exists | boolean | Whether the account exists. | 
| ACME.AcmeAccountInfo.account_uri | string | ACME account URI, or None if account does not exist. | 
| ACME.AcmeAccountInfo.account | unknown | The account information, as retrieved from the ACME server. | 
| ACME.AcmeAccountInfo.orders | unknown | The list of orders. If \`retrieve_orders\` is \`url_list\`, this will be a list of URLs. If \`retrieve_orders\` is \`object_list\`, this will be a list of objects. | 


#### Command Example
```!acme-account-info host="123.123.123.123" "account_key_src"="/etc/letsencrypt/keys/example.com.key" acme_version=2 acme_directory=https://acme-staging-v02.api.letsencrypt.org/directory```

#### Context Example
```json
{
    "ACME": {
        "AcmeAccountInfo": {
            "account": {
                "contact": [
                    "mailto:user@example.com"
                ],
                "createdAt": "2021-07-10T09:53:36Z",
                "initialIp": "123.123.123.123",
                "key": {
                    "e": "AQAB",
                    "kty": "RSA",
                    "n": "pdq0KgKTw2ih3...AgYk"
                },
                "public_account_key": {
                    "e": "AQAB",
                    "kty": "RSA",
                    "n": "pdq0KgKTw2ih3U...97AgYk"
                },
                "status": "valid"
            },
            "account_uri": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345678",
            "changed": false,
            "exists": true,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * account_uri: https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345678
>  * changed: False
>  * exists: True
>  * ## Account
>    * createdAt: 2021-07-10T09:56:36Z
>    * initialIp: 123.123.123.123
>    * status: valid
>    * ### Contact
>      * 0: mailto:user@example.com
>    * ### Key
>      * e: AQAB
>      * kty: RSA
>      * n: pdq0KgKTw2...97AgYk
>    * ### Public_Account_Key
>      * e: AQAB
>      * kty: RSA
>      * n: pdq0KgKTw2ih3...7AgYk


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
| account_email | The email address associated with this account. It will be used for certificate expiration warnings. Note that when `modify_account` is not set to `no` and you also used the `acme_account` module to specify more than one contact for your account, this module will update your account and restrict it to the (at most one) contact email address specified here. | Optional | 
| agreement | URI to a terms of service document you agree to when using the ACME v1 service at `acme_directory`. Default is latest gathered from `acme_directory` URL. This option will only be used when `acme_version` is 1. | Optional | 
| terms_agreed | Boolean indicating whether you agree to the terms of service document. ACME servers can require this to be true. This option will only be used when `acme_version` is not 1. Possible values are: Yes, No. Default is No. | Optional | 
| modify_account | Boolean indicating whether the module should create the account if necessary, and update its contact data. Set to `no` if you want to use the `acme_account` module to manage your account instead, and to avoid accidental creation of a new account using an old key if you changed the account key with `acme_account`. If set to `no`, `terms_agreed` and `account_email` are ignored. Possible values are: Yes, No. Default is Yes. | Optional | 
| challenge | The challenge to be performed. Possible values are: http-01, dns-01, tls-alpn-01. Default is http-01. | Optional | 
| csr | File containing the CSR for the new certificate. Can be created with `openssl req ...`. The CSR may contain multiple Subject Alternate Names, but each one will lead to an individual challenge that must be fulfilled for the CSR to be signed. `Note`: the private key used to create the CSR `must not` be the account key. This is a bad idea from a security point of view, and the CA should not accept the CSR. The ACME server should return an error in this case. | Required | 
| data | The data to validate ongoing challenges. This must be specified for the second run of the module only. The value that must be used here will be provided by a previous use of this module. See the examples for more details. Note that for ACME v2, only the `order_uri` entry of `data` will be used. For ACME v1, `data` must be non-empty to indicate the second stage is active; all needed data will be taken from the CSR. `Note`: the `data` option was marked as `no_log` up to Ansible 2.5. From Ansible 2.6 on, it is no longer marked this way as it causes error messages to be come unusable, and `data` does not contain any information which can be used without having access to the account key or which are not public anyway. | Optional | 
| dest | The destination file for the certificate. Required if `fullchain_dest` is not specified. | Optional | 
| fullchain_dest | The destination file for the full chain (i.e. certificate followed by chain of intermediate certificates). Required if `dest` is not specified. | Optional | 
| chain_dest | If specified, the intermediate certificate will be written to this file. | Optional | 
| remaining_days | The number of days the certificate must have left being valid. If `cert_days &lt; remaining_days`, then it will be renewed. If the certificate is not renewed, module return values will not include `challenge_data`. To make sure that the certificate is renewed in any case, you can use the `force` option. Default is 10. | Optional | 
| deactivate_authzs | Deactivate authentication objects (authz) after issuing a certificate, or when issuing the certificate failed. Authentication objects are bound to an account key and remain valid for a certain amount of time, and can be used to issue certificates without having to re-authenticate the domain. This can be a security concern. Possible values are: Yes, No. Default is No. | Optional | 
| force | Enforces the execution of the challenge and validation, even if an existing certificate is still valid for more than `remaining_days`. This is especially helpful when having an updated CSR e.g. with additional domains for which a new certificate is desired. Possible values are: Yes, No. Default is No. | Optional | 
| retrieve_all_alternates | When set to `yes`, will retrieve all alternate chains offered by the ACME CA. These will not be written to disk, but will be returned together with the main chain as `all_chains`. See the documentation for the `all_chains` return value for details. Possible values are: Yes, No. Default is No. | Optional | 
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key. RSA keys can be created with `openssl genrsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well. Mutually exclusive with `account_key_content`. Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Mutually exclusive with `account_key_src`.<br/>Required if `account_key_src` is not used.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint. Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API. For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates. For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints` For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`. For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`. `Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates. `Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Possible values are: Yes, No. Default is Yes. | Optional | 
| select_crypto_backend | Determines which crypto backend to use. The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`. If set to `openssl`, will try to use the `openssl` binary. If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.AcmeCertificate.cert_days | number | The number of days the certificate remains valid. | 
| ACME.AcmeCertificate.challenge_data | unknown | Per identifier / challenge type challenge data. Since Ansible 2.8.5, only challenges which are not yet valid are returned. | 
| ACME.AcmeCertificate.challenge_data_dns | unknown | List of TXT values per DNS record, in case challenge is \`dns-01\`. Since Ansible 2.8.5, only challenges which are not yet valid are returned. | 
| ACME.AcmeCertificate.authorizations | unknown | ACME authorization data. Maps an identifier to ACME authorization objects. See \`https://tools.ietf.org/html/rfc8555#section-7.1.4\`. | 
| ACME.AcmeCertificate.order_uri | string | ACME order URI. | 
| ACME.AcmeCertificate.finalization_uri | string | ACME finalization URI. | 
| ACME.AcmeCertificate.account_uri | string | ACME account URI. | 
| ACME.AcmeCertificate.all_chains | unknown | When \`retrieve_all_alternates\` is set to \`yes\`, the module will query the ACME server for alternate chains. This return value will contain a list of all chains returned, the first entry being the main chain returned by the server. See \`Section 7.4.2 of RFC8555,https://tools.ietf.org/html/rfc8555#section-7.4.2\` for details. | 


#### Command Example
```!acme-certificate host="123.123.123.123" "account_key_src"="/etc/letsencrypt/keys/example.com.key" dest=/etc/letsencrypt/certs/test.example.com.crt csr=/etc/letsencrypt/csrs/example.com.csr acme_directory=https://acme-v02.api.letsencrypt.org/directory acme_version=2 challenge="dns-01" terms_agreed=1```

#### Context Example
```json
{
    "ACME": {
        "AcmeCertificate": {
            "account_uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123456789",
            "authorizations": {
                "xsoar-example.example.com": {
                    "challenges": [
                        {
                            "status": "pending",
                            "token": "UjnalQ...8OEsJw",
                            "type": "http-01",
                            "url": "https://acme-v02.api.letsencrypt.org/acme/chall-v3/12345678901/4cF9Tg"
                        },
                        {
                            "status": "pending",
                            "token": "UjnalQ...8OEsJw",
                            "type": "dns-01",
                            "url": "https://acme-v02.api.letsencrypt.org/acme/chall-v3/12345678901/J6Svyw"
                        },
                        {
                            "status": "pending",
                            "token": "UjnalQ...8OEsJw",
                            "type": "tls-alpn-01",
                            "url": "https://acme-v02.api.letsencrypt.org/acme/chall-v3/12345678901/Phy50Q"
                        }
                    ],
                    "expires": "2021-07-13T10:05:43Z",
                    "identifier": {
                        "type": "dns",
                        "value": "xsoar-example.example.com"
                    },
                    "status": "pending",
                    "uri": "https://acme-v02.api.letsencrypt.org/acme/authz-v3/12345678901"
                }
            },
            "cert_days": -1,
            "challenge_data": {
                "xsoar-example.example.com": {
                    "dns-01": {
                        "record": "_acme-challenge.xsoar-example.example.com",
                        "resource": "_acme-challenge",
                        "resource_value": "aIt7...MjsnM"
                    },
                    "http-01": {
                        "resource": ".well-known/acme-challenge/UjnalQ...8OEsJw",
                        "resource_value": "UjnalQ...8OEsJw.brMgVl5klrL6Hsd4E1YqcpXU5Mn-jVxqb5MtbbzmMjg"
                    },
                    "tls-alpn-01": {
                        "resource": "xsoar-example.example.com",
                        "resource_original": "dns:xsoar-example.example.com",
                        "resource_value": "aIt7...MjsnM="
                    }
                }
            },
            "challenge_data_dns": {
                "_acme-challenge.xsoar-example.example.com": [
                    "aIt7...MjsnM"
                ]
            },
            "changed": true,
            "finalize_uri": "https://acme-v02.api.letsencrypt.org/acme/finalize/123456789/12345678901",
            "host": "123.123.123.123",
            "order_uri": "https://acme-v02.api.letsencrypt.org/acme/order/123456789/12345678901",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * account_uri: https://acme-v02.api.letsencrypt.org/acme/acct/123456789
>  * cert_days: -1
>  * changed: True
>  * finalize_uri: https://acme-v02.api.letsencrypt.org/acme/finalize/123456789/12345678901
>  * order_uri: https://acme-v02.api.letsencrypt.org/acme/order/123456789/12345678901
>  * ## Authorizations
>    * ### xsoar-example.example.Com
>      * expires: 2021-07-13T10:05:43Z
>      * status: pending
>      * uri: https://acme-v02.api.letsencrypt.org/acme/authz-v3/12345678901
>      * #### Challenges
>      * #### List
>        * status: pending
>        * token: UjnalQ...8OEsJw
>        * type: http-01
>        * url: https://acme-v02.api.letsencrypt.org/acme/chall-v3/12345678901/4cF9Tg
>      * #### List
>        * status: pending
>        * token: UjnalQ...8OEsJw
>        * type: dns-01
>        * url: https://acme-v02.api.letsencrypt.org/acme/chall-v3/12345678901/J6Svyw
>      * #### List
>        * status: pending
>        * token: UjnalQ...8OEsJw
>        * type: tls-alpn-01
>        * url: https://acme-v02.api.letsencrypt.org/acme/chall-v3/12345678901/Phy50Q
>      * #### Identifier
>        * type: dns
>        * value: xsoar-example.example.com
>  * ## Challenge_Data
>    * ### xsoar-example.example.Com
>      * #### Dns-01
>        * record: _acme-challenge.xsoar-example.example.com
>        * resource: _acme-challenge
>        * resource_value: aIt7...MjsnM
>      * #### Http-01
>        * resource: .well-known/acme-challenge/UjnalQ...8OEsJw
>        * resource_value: UjnalQ...8OEsJw.brMgVl5klrL6Hsd4E1YqcpXU5Mn-jVxqb5MtbbzmMjg
>      * #### Tls-Alpn-01
>        * resource: xsoar-example.example.com
>        * resource_original: dns:xsoar-example.example.com
>        * resource_value: aIt7...MjsnM=
>  * ## Challenge_Data_Dns
>    * ### _Acme-Challenge.xsoar-example.example.Com
>      * 0: aIt7...MjsnM


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
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key. RSA keys can be created with `openssl rsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well. Mutually exclusive with `account_key_content`. Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Note that exactly one of `account_key_src`, `account_key_content`, `private_key_src` or `private_key_content` must be specified.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| private_key_src | Path to the certificate's private key. Note that exactly one of `account_key_src`, `account_key_content`, `private_key_src` or `private_key_content` must be specified. | Optional | 
| private_key_content | Content of the certificate's private key.<br/>Note that exactly one of `account_key_src`, `account_key_content`, `private_key_src` or `private_key_content` must be specified.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| revoke_reason | One of the revocation reasonCodes defined in `Section 5.3.1 of RFC5280,https://tools.ietf.org/html/rfc5280#section-5.3.1`. Possible values are `0` (unspecified), `1` (keyCompromise), `2` (cACompromise), `3` (affiliationChanged), `4` (superseded), `5` (cessationOfOperation), `6` (certificateHold), `8` (removeFromCRL), `9` (privilegeWithdrawn), `10` (aACompromise). | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint. Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API. For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates. For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints` For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`. For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`. `Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates. `Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Possible values are: Yes, No. Default is Yes. | Optional | 
| select_crypto_backend | Determines which crypto backend to use. The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`. If set to `openssl`, will try to use the `openssl` binary. If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


### acme-challenge-cert-helper
***
Prepare certificates required for ACME challenges such as C(tls-alpn-01)
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/acme_challenge_cert_helper_module.html


#### Base Command

`acme-challenge-cert-helper`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| challenge | The challenge type. Possible values are: tls-alpn-01. | Required | 
| challenge_data | The `challenge_data` entry provided by `acme_certificate` for the challenge. | Required | 
| private_key_src | Path to a file containing the private key file to use for this challenge certificate. Mutually exclusive with `private_key_content`. | Optional | 
| private_key_content | Content of the private key to use for this challenge certificate. Mutually exclusive with `private_key_src`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.AcmeChallengeCertHelper.domain | string | The domain the challenge is for. The certificate should be provided if this is specified in the request's the \`Host\` header. | 
| ACME.AcmeChallengeCertHelper.identifier_type | string | The identifier type for the actual resource identifier. Will be \`dns\` or \`ip\`. | 
| ACME.AcmeChallengeCertHelper.identifier | string | The identifier for the actual resource. Will be a domain name if the type is \`dns\`, or an IP address if the type is \`ip\`. | 
| ACME.AcmeChallengeCertHelper.challenge_certificate | string | The challenge certificate in PEM format. | 
| ACME.AcmeChallengeCertHelper.regular_certificate | string | A self-signed certificate for the challenge domain. If no existing certificate exists, can be used to set-up https in the first place if that is needed for providing the challenge. | 

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
| url | The URL to send the request to. Must be specified if `method` is not `directory-only`. | Optional | 
| method | The method to use to access the given URL on the ACME server. The value `post` executes an authenticated POST request. The content must be specified in the `content` option. The value `get` executes an authenticated POST-as-GET request for ACME v2, and a regular GET request for ACME v1. The value `directory-only` only retrieves the directory, without doing a request. Possible values are: get, post, directory-only. Default is get. | Optional | 
| content | An encoded JSON object which will be sent as the content if `method` is `post`. Required when `method` is `post`, and not allowed otherwise. | Optional | 
| fail_on_acme_error | If `method` is `post` or `get`, make the module fail in case an ACME error is returned. Possible values are: Yes, No. Default is Yes. | Optional | 
| account_key_src | Path to a file containing the ACME account RSA or Elliptic Curve key. RSA keys can be created with `openssl genrsa ...`. Elliptic curve keys can be created with `openssl ecparam -genkey ...`. Any other tool creating private keys in PEM format can be used as well. Mutually exclusive with `account_key_content`. Required if `account_key_content` is not used. | Optional | 
| account_key_content | Content of the ACME account RSA or Elliptic Curve key.<br/>Mutually exclusive with `account_key_src`.<br/>Required if `account_key_src` is not used.<br/>`Warning`: the content will be written into a temporary file, which will be deleted by Ansible when the module completes. Since this is an important private key — it can be used to change the account key, or to revoke your certificates without knowing their private keys —, this might not be acceptable.<br/>In case `cryptography` is used, the content is not written into a temporary file. It can still happen that it is written to disk by Ansible in the process of moving the module with its argument to the node where it is executed. | Optional | 
| account_uri | If specified, assumes that the account URI is as given. If the account key does not match this account, or an account with this URI does not exist, the module fails. | Optional | 
| acme_version | The ACME version of the endpoint. Must be 1 for the classic Let's Encrypt and Buypass ACME endpoints, or 2 for standardized ACME v2 endpoints. Possible values are: 1, 2. Default is 1. | Optional | 
| acme_directory | The ACME directory to use. This is the entry point URL to access CA server API. For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create technically correct, but untrusted certificates. For Let's Encrypt, all staging endpoints can be found here: `https://letsencrypt.org/docs/staging-environment/`. For Buypass, all endpoints can be found here: `https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints` For Let's Encrypt, the production directory URL for ACME v1 is `https://acme-v01.api.letsencrypt.org/directory`, and the production directory URL for ACME v2 is `https://acme-v02.api.letsencrypt.org/directory`. For Buypass, the production directory URL for ACME v2 and v1 is `https://api.buypass.com/acme/directory`. `Warning`: So far, the module has only been tested against Let's Encrypt (staging and production), Buypass (staging and production), and `Pebble testing server,https://github.com/letsencrypt/Pebble`. Default is https://acme-staging.api.letsencrypt.org/directory. | Optional | 
| validate_certs | Whether calls to the ACME directory will validate TLS certificates. `Warning`: Should `only ever` be set to `no` for testing purposes, for example when testing against a local Pebble server. Possible values are: Yes, No. Default is Yes. | Optional | 
| select_crypto_backend | Determines which crypto backend to use. The default choice is `auto`, which tries to use `cryptography` if available, and falls back to `openssl`. If set to `openssl`, will try to use the `openssl` binary. If set to `cryptography`, will try to use the `cryptography,https://cryptography.io/` library. Possible values are: auto, cryptography, openssl. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ACME.AcmeInspect.directory | unknown | The ACME directory's content | 
| ACME.AcmeInspect.headers | unknown | The request's HTTP headers \(with lowercase keys\) | 
| ACME.AcmeInspect.output_text | string | The raw text output | 
| ACME.AcmeInspect.output_json | unknown | The output parsed as JSON | 


#### Command Example
```!acme-inspect host="123.123.123.123" acme_directory="https://acme-staging-v02.api.letsencrypt.org/directory" acme_version="2" method="directory-only" ```

#### Context Example
```json
{
    "ACME": {
        "AcmeInspect": {
            "changed": false,
            "directory": {
                "d3x8YeEROW0": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
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
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Directory
>    * d3x8YeEROW0: https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417
>    * keyChange: https://acme-staging-v02.api.letsencrypt.org/acme/key-change
>    * newAccount: https://acme-staging-v02.api.letsencrypt.org/acme/new-acct
>    * newNonce: https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce
>    * newOrder: https://acme-staging-v02.api.letsencrypt.org/acme/new-order
>    * revokeCert: https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert
>    * ### Meta
>      * termsOfService: https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf
>      * website: https://letsencrypt.org/docs/staging-environment/
>      * #### Caaidentities
>        * 0: letsencrypt.org


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
