Uses incapsula to manage sites and IPs.

## Configure Imperva Incapsula in Cortex


| **Parameter** | **Required** |
| --- | --- |
| API ID | True |
| API key | True |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### incap-add-managed-account

***
Use this operation to add a new account that should be managed by the account of the API client (the parent account). The new account will be configured according to the preferences set for the parent account by Incapsula. Depending on these preferences, an activation e-mail will be sent to the specified e-mail address. The user responds to the activation e-mail, selects a password, and can then log directly into the Incapsula console. The same e-mail address can also be used to send system notifications to the account. The new account is identified by a numeric value as provided by Incapsula in the response in the field account_id.

#### Base Command

`incap-add-managed-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address. For example: "joe@example.com". | Required | 
| parent_id | The newly created account's parent id. If not specified, the invoking account will be assigned as the parent. | Optional | 
| user_name | The account owner's name. For example: 'John Doe'. | Optional | 
| plan_id | An identifier of the plan to assign to the new account. For example, ent100 for the Enterprise 100 plan. | Optional | 
| ref_id | Customer specific identifier for this operation. | Optional | 
| account_name | Account name. | Optional | 
| log_level | Available only for Enterprise Plan customers that purchased the Logs Integration SKU. Sets the log reporting level for the site. Options are “full”, “security”, “none” and "default". | Optional | 
| logs_account_id | Available only for Enterprise Plan customers that purchased the Logs Integration SKU. Numeric identifier of the account that purchased the logs integration SKU and which collects the logs. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 

#### Context Output

There is no context output for this command.
### incap-list-managed-accounts

***
Use this operation to get the list of accounts that are managed by account of the API client (the parent account).

#### Base Command

`incap-list-managed-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 
| page_size | The number of objects to return in the response.<br/>Default: 50<br/>Maximum: 100. | Optional | 
| page_num | The page to return starting from 0. Default: 0. | Optional | 

#### Context Output

There is no context output for this command.
### incap-add-subaccount

***
Use this operation to add a new sub account to be managed by the account of the API client (the parent account).

#### Base Command

`incap-add-subaccount`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sub_account_name | The name of the sub account. | Required | 
| parent_id | The newly created account's parent id. If not specified, the invoking account will be assigned as the parent. | Optional | 
| user_name | The account owner's name. For example: 'John Doe'. | Optional | 
| ref_id | Customer specific identifier for this operation. | Optional | 
| log_level | Available only for Enterprise Plan customers that purchased the Logs Integration SKU. Sets the log reporting level for the site. Options are “full”, “security”, “none” and "default". | Optional | 
| logs_account_id | Available only for Enterprise Plan customers that purchased the Logs Integration SKU. Numeric identifier of the account that purchased the logs integration SKU and which collects the logs. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 

#### Context Output

There is no context output for this command.
### incap-list-subaccounts

***
Use this operation to get a list of sub accounts that are managed by the account of the API client (the parent account).

#### Base Command

`incap-list-subaccounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 
| page_size | The number of objects to return in the response.<br/>Default: 50<br/>Maximum: 100. | Optional | 
| page_num | The page to return starting from 0. Default: 0. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-account-status

***
Use this operation to get information about the account of the API client or one of its managed accounts.

#### Base Command

`incap-get-account-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 

#### Context Output

There is no context output for this command.
### incap-modify-account-configuration

***
Use this operation to change the configuration of the account of the API client or one of its managed accounts.

#### Base Command

`incap-modify-account-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 
| param | Name of the configuration parameter to set.<br/>Possible values: name \| email \| plan_id \| error_page_template \| support_all_tls_versions. Possible values are: name, email, plan_id, error_page_template, support_all_tls_versions. | Required | 
| value | According to the configuration paramater used.<br/>For name - the updated name, for e-mail - the updated e-mail address.<br/>For plan_id - a plan id.<br/>For error_page_template - a Base64 encoded template for an error page.<br/>For log_level - Available only for Enterprise Plan customers that purchased the Logs Integration SKU. Sets the log reporting level for the site. Possible values: full, security, none, default<br/>For support_all_tls_versions - Use this operation to allow sites in the account to support all TLS versions for connectivity between clients (visitors) and the Incapsula service. When this option is set, you can then enable the option per site to support all TLS versions. Possible values: true, false. Note: To remain PCI-compliant, do not enable this option. | Required | 

#### Context Output

There is no context output for this command.
### incap-set-account-log-level

***
Use this operation to change the account log configuration.

#### Base Command

`incap-set-account-log-level`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 
| log_level | Sets the log reporting level for the site.<br/>Possible values: full, security, none, default<br/>Available only for Enterprise Plan customers that purchased the Log Integration SKU. Possible values are: full, security, none, default, support_all_tls_versions. | Required | 

#### Context Output

There is no context output for this command.
### incap-test-account-s3-connection

***
Use this operation to check that a connection can be created with your Amazon S3 bucket.

#### Base Command

`incap-test-account-s3-connection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 
| bucket_name | S3 bucket name. | Required | 
| access_key | S3 access key. | Required | 
| secret_key | 3 secret key. | Required | 
| save_on_success | Save this configuration if the test connection was successful. Default value: false. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### incap-test-account-sftp-connection

***
Use this operation to check that a connection can be created with your SFTP storage.

#### Base Command

`incap-test-account-sftp-connection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 
| host | The IP address of your SFTP server. | Required | 
| user_name | A user name that will be used to log in to the SFTP server. | Required | 
| password | A corresponding password for the user account used to log in to the SFTP server. | Required | 
| destination_folder | The path to the directory on the SFTP server. | Required | 
| save_on_success | Save this configuration if the test connection was successful. Default value: false. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### incap-set-account-s3-log-storage

***
Use this operation to configure your Amazon cloud storage. Once configured, Incapsula logs will be uploaded to the selected location.

#### Base Command

`incap-set-account-s3-log-storage`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 
| bucket_name | S3 bucket name. | Required | 
| access_key | S3 access key. | Required | 
| secret_key | 3 secret key. | Required | 

#### Context Output

There is no context output for this command.
### incap-set-account-sftp-log-storage

***
Use this operation to configure your SFTP server storage. Once configured, Incapsula logs will be uploaded to the selected location.

#### Base Command

`incap-set-account-sftp-log-storage`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 
| host | The IP address of your SFTP server. | Required | 
| user_name | A user name that will be used to log in to the SFTP server. | Required | 
| password | A corresponding password for the user account used to log in to the SFTP server. | Required | 
| destination_folder | The path to the directory on the SFTP server. | Required | 

#### Context Output

There is no context output for this command.
### incap-set-account-default-log-storage

***
Use this operation to have your logs saved on Incapsula servers. Once configured, the logs can be retrieved by API calls.

#### Base Command

`incap-set-account-default-log-storage`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-get-account-login-token

***
Tokens are used instead of user/password based authentication to log in to the Incapsula management console.  Use this operation to generate a token for an account. The token is valid for 15 minutes.
In order to use the token, the user must use the following link:  https://my.incapsula.com/?token={generated_token}

#### Base Command

`incap-get-account-login-token`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 

#### Context Output

There is no context output for this command.
### incap-delete-managed-account

***
Use this operation to delete an account.

#### Base Command

`incap-delete-managed-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Optional | 

#### Context Output

There is no context output for this command.
### incap-delete-subaccount

***
Use this operation to delete a sub account.

#### Base Command

`incap-delete-subaccount`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sub_account_id | Numeric identifier of the sub account to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-get-account-audit-events

***
Use this operation to get audit events for an account.

#### Base Command

`incap-get-account-audit-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 
| time_range | Time range to fetch data for. For a detailed description, see https://docs.incapsula.com/Content/API/api.htm. | Optional | 
| start | Start date in milliseconds since 1970. For a detailed description, see https://docs.incapsula.com/Content/API/api.htm. | Optional | 
| end | End date in milliseconds since 1970. For a detailed description, see https://docs.incapsula.com/Content/API/api.htm. | Optional | 
| type | The api key of the event type, such as audit.account_login. | Optional | 
| page_size | The number of objects to return in the response.<br/>Default: 50.<br/>Maximum: 100. | Optional | 
| page_num | The page to return starting from 0. Default: 0. | Optional | 

#### Context Output

There is no context output for this command.
### incap-set-account-default-data-storage-region

***
Use this operation to set the default data region of the account for newly created sites.

#### Base Command

`incap-set-account-default-data-storage-region`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 
| data_storage_region | The data region to use. Possible values are: APAC, EU, US, DEFAULT. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-account-default-data-storage-region

***
Use this operation to get the default data region of the account.

#### Base Command

`incap-get-account-default-data-storage-region`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-add-site

***
Add a new site to an account. If the site already exists, its status is returned

#### Base Command

`incap-add-site`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name of the site. For example: www.example.com, hello.example.com, example.com. | Required | 
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 
| ref_id | Customer specific identifier for this operation. | Optional | 
| send_site_setup_emails | If this value is "false", end users will not get emails about the add site process such as "DNS instructions" and "SSL setup". | Optional | 
| site_ip | Manually set the web server IP/cname. This option is only available for specific accounts. Please contact support for more details. | Optional | 
| force_ssl | If this value is "true", manually set the site to support SSL. This option is only available for sites with manually configured IP/cname and for specific accounts. Please contact support for more details. | Optional | 
| log_level | Available only for Enterprise Plan customers that purchased the Logs Integration SKU. Sets the log reporting level for the site. Options are “full”, “security”, “none” and "default". | Optional | 
| logs_account_id | Available only for Enterprise Plan customers that purchased the Logs Integration SKU. Numeric identifier of the account that purchased the logs integration SKU and which collects the logs. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-site-status

***
Use this operation to get the status of a site

#### Base Command

`incap-get-site-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| tests | List of tests to run on site before returning its status. A comma separated list of one of: domain_validation, services, dns. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-domain-approver-email

***
Use this operation to get the list of email addresses that can be used when adding an SSL site

#### Base Command

`incap-get-domain-approver-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name of the site. For example: www.example.com, hello.example.com, example.com. | Optional | 

#### Context Output

There is no context output for this command.
### incap-modify-site-configuration

***
Use this operation to change one of the basic configuration settings of the site. To watch param table, visit https://my.incapsula.com/api/docs/v1/sites#modifySiteConfig

#### Base Command

`incap-modify-site-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| param | Name of configuration parameter to set. | Required | 
| value | According to the param value. | Required | 

#### Context Output

There is no context output for this command.
### incap-modify-site-log-level

***
Use this operation to change the site log configuration

#### Base Command

`incap-modify-site-log-level`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| log_level | Available only for Enterprise Plan customers that purchased the Logs Integration SKU. Sets the log reporting level for the site. Options are “full”, “security”, “none” and "default". | Optional | 

#### Context Output

There is no context output for this command.
### incap-modify-site-tls-support

***
Use this operation to support all TLS versions for the site for connectivity between clients (visitors) and the Incapsula service. To remain PCI-compliant, do not enable this option.

#### Base Command

`incap-modify-site-tls-support`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| support_all_tls_versions | Support all TLS versions. Default value: false. Possible values are: true, false. | Required | 

#### Context Output

There is no context output for this command.
### incap-modify-site-scurity-config

***
Use this operation to change the security configuration of a site

#### Base Command

`incap-modify-site-scurity-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| rule_id | ID of the security rule to change. For possible values see the security section in the Get Site Status API call. | Required | 
| block_bad_bots | Whether or not to block bad bots. One of: true, false. | Optional | 
| challenge_suspected_bots | Whether or not to send a challenge to clients that are suspected to be bad bots (CAPTCHA for example). One of: true, false. | Optional | 
| activation_mode | One of the following: off (security measures are disabled even if site is under a DDoS attack), auto (security measures will be activated automatically when the system suspects site is under a DDoS attack), on (security measures are enabled even if site is not under a DDoS attack). The syntax is as follows: api.threats.ddos.activation_mode.( e.g. for "off", use "api.threats.ddos.activation_mode.off" ). | Optional | 
| security_rule_action | The action that should be taken when a threat is detected, for example: api.threats.action.block_ip. Different actions are allowed per different threats, e.g. backdoors may only be quarantined, ignored or trigger an alert. For possible values see below. | Optional | 
| quarantined_urls | A comma seperated list of encoded URLs to be kept in quarantine. | Optional | 
| ddos_traffic_threshold | Consider site to be under DDoS if the request rate is above this threshold. The valid values are 10, 20, 50, 100, 200, 500, 750, 1000, 2000, 3000, 4000, 5000. | Optional | 

#### Context Output

There is no context output for this command.
### incap-modify-site-acl-config

***
Use this operation to change the ACL configuration of a site. To modify the configuration for a specific ACL rule, its values are required, as documented below. To delete an entire ACL list, send an empty string as the list values

#### Base Command

`incap-modify-site-acl-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| rule_id | The id of the acl, e.g api.acl.blacklisted_ips. One of: api.acl.blacklisted_countries, api.acl.blacklisted_urls, api.acl.blacklisted_ips, api.acl.whitelisted_ips. | Required | 
| urls | A comma separated list of resource paths. For example, /home and /admin/index.html are resource paths, however http://www.example.com/home is not. Each URL should be encoded separately using percent encoding as specified by RFC 3986 (http://tools.ietf.org/html/rfc3986#section-2.1). An empty URL list will remove all URLs. | Optional | 
| url_patterns | A comma seperated list of url patterns, one of: contains \| equals \| prefix \| suffix \| not_equals \| not_contain \| not_prefix \| not_suffix. The patterns should be in accordance with the matching urls sent by the urls parameter. | Optional | 
| countries | A comma seperated list of country codes. | Optional | 
| continents | A comma seperated list of continent codes. | Optional | 
| ips | A comma seperated list of IPs or IP ranges, e.g: 192.168.1.1, 192.168.1.1-192.168.1.100 or 192.168.1.1/24. | Optional | 

#### Context Output

There is no context output for this command.
### incap-modify-site-wl-config

***
Use this operation to set allow lists to security rules or ACLs. To update an existing allow list, send its ID in the id parameter. If the id parameter does not exist a new allow list will be created

#### Base Command

`incap-modify-site-wl-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| rule_id | The id of the rule (either a security or an acl rule), e.g api.acl.blacklisted_ips. See other examples below. | Required | 
| whitelist_id | The id (an integer) of the allow list to be set. This field is optional - in case no id is supplied, a new allow list will be created. | Optional | 
| delete_whitelist | An optional boolean parameter, in case it is set to "true" and a allow list id is sent, then the allow list will be deleted. | Optional | 
| urls | A comma separated list of resource paths. For example, /home and /admin/index.html are resource paths, however http://www.example.com/home is not. Each URL should be encoded separately using percent encoding as specified by RFC 3986 (http://tools.ietf.org/html/rfc3986#section-2.1). An empty URL list will remove all URLs. | Optional | 
| countries | A comma seperated list of country codes. | Optional | 
| continents | A comma seperated list of continent codes. | Optional | 
| ips | A comma seperated list of IPs or IP ranges, e.g: 192.168.1.1, 192.168.1.1-192.168.1.100 or 192.168.1.1/24. | Optional | 
| client_app_types | A comma seperated list of client application types. | Optional | 
| client_apps | A comma seperated list of client application ids. | Optional | 
| parameters | A comma seperated list of encoded user agents. | Optional | 
| user_agents | A comma seperated list of encoded user agents. | Optional | 

#### Context Output

There is no context output for this command.
### incap-delete-site

***
Delete the site

#### Base Command

`incap-delete-site`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-list-sites

***
List sites for an account

#### Base Command

`incap-list-sites`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 
| page_size | The number of objects to return in the response. Defaults to 50. | Optional | 
| page_num | The page to return starting from 0. Default to 0. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-site-report

***
Use this operation to get a report for a site. Reports are sent using Base64 encoding

#### Base Command

`incap-get-site-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| report | The report to get, one of: pci-compliance. | Required | 
| format | The format to get the report in, one of: pdf \| html. | Required | 
| time_range | Time range to fetch data for. See the introduction of the API documentation for a detailed description. | Required | 
| start | Start date in milliseconds since 1970. See the introduction of the API documentation for a detailed description. | Optional | 
| end | End date in milliseconds since 1970. See the introduction of the API documentation for a detailed description. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-site-html-injection-rules

***
Use this operation to list all the HTML Injection rules.

#### Base Command

`incap-get-site-html-injection-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-add-site-html-injection-rule

***
Use this operation to add a new HTML injection rule or to replace an existing rule.

#### Base Command

`incap-add-site-html-injection-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| url | The URL where the content is injected. | Required | 
| url_pattern | The url pattern. One of: contains \| not_contains \| equals \| not_equals \| prefix \| suffix \| not_prefix \| not_suffix. Possible values are: contains, not_contains, equals, not_equals, prefix, suffix, not_prefix, not_suffix. | Required | 
| location | The location of the injection inside the URL ('head' or 'body_end'). Possible values are: head, body_end. | Required | 
| content | The injected HTML snippet, Base64-encoded. | Optional | 

#### Context Output

There is no context output for this command.
### incap-delete-site-html-injection-rule

***
Use this operation to removes an existing HTML injection rule. To confirm the removal, set the parameter delete_content to true.

#### Base Command

`incap-delete-site-html-injection-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| url | The URL where the content is injected. | Required | 
| url_pattern | The url pattern. One of: contains \| not_contains \| equals \| not_equals \| prefix \| suffix \| not_prefix \| not_suffix. Possible values are: contains, not_contains, equals, not_equals, prefix, suffix, not_prefix, not_suffix. | Required | 
| location | The location of the injection inside the URL ('head' or 'body_end'). Possible values are: head, body_end. | Required | 
| delete_content | Whether or not to delete existing HTML content.  Possible values: true/false. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### incap-create-new-csr

***
Use this operation to create a certificate signing request (CSR) for your site

#### Base Command

`incap-create-new-csr`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| email | Email address. For example: joe@example.com. | Optional | 
| organization | The legal name of your organization. This should not be abbreviated or include suffixes such as Inc., Corp., or LLC. | Optional | 
| organization_unit | The division of your organization handling the certificate. For example, "IT Department". | Optional | 
| country | The two-letter ISO code for the country where your organization is located. | Optional | 
| state | The state/region where your organization is located. This should not be abbreviated. | Optional | 
| city | The city where your organization is located. | Optional | 

#### Context Output

There is no context output for this command.
### incap-upload-certificate

***
Use this operation to upload custom certificate for your site. The following SSL certificate file formats are supported: PFX, PEM, CER

#### Base Command

`incap-upload-certificate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate o. | Required | 
| certificate | The new certificate. | Required | 
| private_key | The private key of the certificate in base64 format. Optional in case of PFX certificate file format. | Optional | 
| passphrase | The passphrase used to protect your SSL certificate. | Optional | 

#### Context Output

There is no context output for this command.
### incap-remove-custom-integration

***
Use this operation to remove custom certificate

#### Base Command

`incap-remove-custom-integration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-move-site

***
Use this operation to move a site from one account to another. You can move a site from a master account to one of its sub accounts, or from one sub account to another.

#### Base Command

`incap-move-site`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| destination_account_id | The numeric identifier of the account which the site will be moved to. | Required | 

#### Context Output

There is no context output for this command.
### incap-check-compliance

***
Check site’s associated SANs for CAA compliance. If a given SAN is compliant, its SSL domain validation status is updated accordingly.
This operation returns an updated list of the site’s associated SANs that are not compliant. An empty list indicates that all SANs are compliant.

#### Base Command

`incap-check-compliance`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-set-site-data-storage-region

***
Use this operation to set the site's data storage region.

#### Base Command

`incap-set-site-data-storage-region`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| data_storage_region | The data region to use. Possible values are: APAC, EU, US. | Required | 

#### Context Output

There is no context output for this command.
### incap-get-site-data-storage-region

***
Use this operation to get the site's data storage region.

#### Base Command

`incap-get-site-data-storage-region`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-set-site-data-storage-region-geo-override

***
Use this operation to set the data storage region for each new site based on the geolocation of the origin server.

#### Base Command

`incap-set-site-data-storage-region-geo-override`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| override_site_regions_by_geo | A boolean parameter. If it is set to "true", the data storage region for each new site will be based on the geolocation of the origin server. Possible values are: true, false. | Required | 
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-site-data-storage-region-geo-override

***
Use this operation to check if the data storage region for each new site is based on the geolocation of the origin server.

#### Base Command

`incap-get-site-data-storage-region-geo-override`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 

#### Context Output

There is no context output for this command.
### incap-purge-site-cache

***
 Use this operation to purge all cached content on our proxy servers for a specific site. Our Proxy servers keep cached content of your sites in order to accelerate page load times for your users. When you want this cached content to be refreshed (for example, after making adjustments in your site) you can use this API call. In order to purge the entire cached content for this site just use the API call with no parameters. If you want to purge a specific resource add the resource name as parameter

#### Base Command

`incap-purge-site-cache`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| purge_pattern | The pattern of the resource to be purged from the cache. For example: (1) Resource_name - resources that contain Resource_name will be purged, (2) ^Resource_name - resources that start with Resource_name will be purged, and (3) Resource_name$ - resources that end with Resource_name will be purged. | Optional | 

#### Context Output

There is no context output for this command.
### incap-modify-cache-mode

***
Use this operation to edit basic site caching settings

#### Base Command

`incap-modify-cache-mode`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| cache_mode | disable \| static_only \| static_and_dynamic \| aggressive : default Static_Only. | Required | 
| dynamic_cache_duration | Profile dynamic pages and cache duration, pass number followed by "_" and one of: hr \| min \| sec \| days \| weeks: default: 5_min. | Optional | 
| aggressive_cache_duration | Cache resource duration, pass number followed by "_" and one of: hr \| min \| sec \| days \| weeks: default: 1_hr. | Optional | 

#### Context Output

There is no context output for this command.
### incap-purge-resources

***
Use this operation to purge site resources

#### Base Command

`incap-purge-resources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| resource_url | Comma seperated list of URLs where the resource is located. | Optional | 
| resource_pattern | Comma seperated list of pattern, one of: contains \| equals \| prefix \| suffix \| not_equals \| not_contains \| not_prefix \| not_suffix. | Optional | 
| should_purge_all_site_resources | Should purge all cached resources on site. | Optional | 

#### Context Output

There is no context output for this command.
### incap-modify-caching-rules

***
Use this operation to set-up advanced caching rules

#### Base Command

`incap-modify-caching-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| always_cache_resource_url | Comma seperated list of always cache resources url. | Optional | 
| always_cache_resource_pattern | Comma seperated list of always cache resources pattern, one of: contains \| equals \| prefix \| suffix \| not_equals \| not_contains \| not_prefix \| not_suffix. | Optional | 
| always_cache_resource_duration | Duration that resources will be in cache, pass number followed by "_" and one of: hr \| min \| sec \| days \| weeks. Either provide a comma seperated list of duration expressions, matching the number of always cache rules, or a single duration expression to be used for all always cache rules. | Optional | 
| never_cache_resource_url | Comma seperated list of never cache resources url. | Optional | 
| never_cahce_resource_pattern | Comma seperated list of cached headers seperated with comma. | Optional | 
| clear_always_cache_rules | An optional boolean parameter, in case it is set to "true", the site's always cache rules will be cleared. | Optional | 
| clear_never_cache_rules | An optional boolean parameter, in case it is set to "true", the site's never cache rules will be cleared. | Optional | 
| clear_cache_headers_rules | An optional boolean parameter, in case it is set to "true", the site's cache headers rules will be cleared. | Optional | 

#### Context Output

There is no context output for this command.
### incap-set-advanced-caching-settings

***
Use this operation to modify advanced caching settings. For more information, https://my.incapsula.com/api/docs/v1/sites#modifyAdvancedCachingSettings

#### Base Command

`incap-set-advanced-caching-settings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| param | Name of configuration parameter to set. | Optional | 
| value | According to the param value. | Optional | 

#### Context Output

There is no context output for this command.
### incap-purge-hostname-from-cache

***
Use this operation to purge the hostname from the cache. This API is for customers who use the same CNAME provided by Incapsula for multiple hostnames and would like to change the CNAME for a particular hostname. Purging the hostname is required for the CNAME change to take effect

#### Base Command

`incap-purge-hostname-from-cache`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | The hostname to purge from cache. | Required | 

#### Context Output

There is no context output for this command.
### incap-site-get-xray-link

***
Use this operation to get a URL that enables debug headers on a specific site.

#### Base Command

`incap-site-get-xray-link`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-list-site-rule-revisions

***
Use this operation to list revisions of a rule (Delivery Rules or IncapRules).

#### Base Command

`incap-list-site-rule-revisions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| rule_id | Rule ID. | Required | 

#### Context Output

There is no context output for this command.
### incap-add-site-rule

***
Use this operation to add a rule (Delivery Rules or IncapRules).

#### Base Command

`incap-add-site-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| name | Rule name. | Optional | 
| action | Rule action. Possible values are: RULE_ACTION_REDIRECT, RULE_ACTION_REWRITE_URL, RULE_ACTION_REWRITE_HEADER, RULE_ACTION_REWRITE_COOKIE, RULE_ACTION_DELETE_HEADER, RULE_ACTION_DELETE_COOKIE, RULE_ACTION_FORWARD_TO_DC, RULE_ACTION_ALERT, RULE_ACTION_BLOCK, RULE_ACTION_BLOCK_USER, RULE_ACTION_BLOCK_IP, RULE_ACTION_RETRY, RULE_ACTION_INTRUSIVE_HTML, RULE_ACTION_CAPTCHA. | Optional | 
| filter | Rule will trigger only a request that matches this filter. For more details on filter guidelines, see https://docs.incapsula.com/Content/IncapRules/syntax-guide.htm<br/>The filter may contain up to 400 characters. | Optional | 
| response_code | Redirect rule's response code. Possible values are: 301, 302, 303, 307, 308. | Optional | 
| protocol | Protocol. | Optional | 
| add_missing | Add cookie or header if it doesn't exist (Rewrite cookie rule only). | Optional | 
| from | The pattern to rewrite.<br/>RULE_ACTION_REWRITE_URL - The URL to rewrite.<br/>RULE_ACTION_REWRITE_HEADER - The header value to rewrite.<br/>RULE_ACTION_REWRITE_COOKIE - The cookie value to rewrite. | Optional | 
| to | The pattern to change to.<br/>RULE_ACTION_REWRITE_URL - The URL to change to.<br/>RULE_ACTION_REWRITE_HEADER - The header value to change to.<br/>RULE_ACTION_REWRITE_COOKIE - The cookie value to change to. | Optional | 
| rewrite_name | Name of cookie or header to rewrite. Applies only for RULE_ACTION_REWRITE_COOKIE and RULE_ACTION_REWRITE_HEADER. | Optional | 
| dc_id | Data center to forward request to. Applies only for RULE_ACTION_FORWARD_TO_DC. | Optional | 
| is_test_mode | Make rule apply only for IP address the API request was sent from. | Optional | 
| lb_algorithm | Data center load balancing algorithm. Possible values are: LB_LEAST_PENDING_REQUESTS, LB_LEAST_OPEN_CONNECTIONS, LB_SOURCE_IP_HASH, RANDOM. | Optional | 

#### Context Output

There is no context output for this command.
### incap-edit-site-rule

***
Use this operation to edit an existing rule (Delivery Rules or IncapRules).

#### Base Command

`incap-edit-site-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID. | Required | 
| name | Rule name. | Optional | 
| action | Rule action. Possible values are: RULE_ACTION_REDIRECT, RULE_ACTION_REWRITE_URL, RULE_ACTION_REWRITE_HEADER, RULE_ACTION_REWRITE_COOKIE, RULE_ACTION_DELETE_HEADER, RULE_ACTION_DELETE_COOKIE, RULE_ACTION_FORWARD_TO_DC, RULE_ACTION_ALERT, RULE_ACTION_BLOCK, RULE_ACTION_BLOCK_USER, RULE_ACTION_BLOCK_IP, RULE_ACTION_RETRY, RULE_ACTION_INTRUSIVE_HTML, RULE_ACTION_CAPTCHA. | Optional | 
| filter | Rule will trigger only a request that matches this filter. For more details on filter guidelines, see https://docs.incapsula.com/Content/IncapRules/syntax-guide.htm<br/>The filter may contain up to 400 characters. | Optional | 
| response_code | Redirect rule's response code. Possible values are: 301, 302, 303, 307, 308. | Optional | 
| protocol | Protocol. | Optional | 
| add_missing | Add cookie or header if it doesn't exist (Rewrite cookie rule only). | Optional | 
| from | The pattern to rewrite.<br/>RULE_ACTION_REWRITE_URL - The URL to rewrite.<br/>RULE_ACTION_REWRITE_HEADER - The header value to rewrite.<br/>RULE_ACTION_REWRITE_COOKIE - The cookie value to rewrite. | Optional | 
| to | The pattern to change to.<br/>RULE_ACTION_REWRITE_URL - The URL to change to.<br/>RULE_ACTION_REWRITE_HEADER - The header value to change to.<br/>RULE_ACTION_REWRITE_COOKIE - The cookie value to change to. | Optional | 
| rewrite_name | Name of cookie or header to rewrite. Applies only for RULE_ACTION_REWRITE_COOKIE and RULE_ACTION_REWRITE_HEADER. | Optional | 
| dc_id | Data center to forward request to. Applies only for RULE_ACTION_FORWARD_TO_DC. | Optional | 
| is_test_mode | Make rule apply only for IP address the API request was sent from. | Optional | 
| lb_algorithm | Data center load balancing algorithm. Possible values are: LB_LEAST_PENDING_REQUESTS, LB_LEAST_OPEN_CONNECTIONS, LB_SOURCE_IP_HASH, RANDOM. | Optional | 

#### Context Output

There is no context output for this command.
### incap-enable-site-rule

***
Use this operation to enable or disable a rule (Delivery Rules or IncapRules).

#### Base Command

`incap-enable-site-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID. | Required | 
| name | Rule name. | Optional | 
| enable | When true, the rule will be enabled. Set to false to disable. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### incap-delete-site-rule

***
Use this operation to delete a rule (Delivery Rules or IncapRules).

#### Base Command

`incap-delete-site-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID. | Required | 
| name | Rule name. | Optional | 
| enable | When true, the rule will be enabled. Set to false to disable. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### incap-list-site-rules

***
Use this operation to list rules (Delivery Rules and IncapRules) for a given site.

#### Base Command

`incap-list-site-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| include_ad_rules | Whether or not delivery rules should be included. Defaults to "Yes". Possible values are: Yes, No. | Optional | 
| include_incap_rules | Whether or not security rules be included. Defaults to "Yes". Possible values are: Yes, No. | Optional | 
| page_size | The number of objects to return in the response.<br/>Default is 50.<br/>Maximum: 100. | Optional | 
| page_num | The page to return starting from 0. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### incap-revert-site-rule

***
Revert a rule (Delivery Rule or IncapRule) using an existing revision.

#### Base Command

`incap-revert-site-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| rule_id | Rule ID. | Required | 
| revision_id | ID of the revision to revert to. Revision ID can be found using !incap-list-site-rule-revisions. | Required | 

#### Context Output

There is no context output for this command.
### incap-set-site-rule-priority

***
Use this operation to change a Delivery Rule's priority.

#### Base Command

`incap-set-site-rule-priority`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID. | Required | 
| priority | New priority for the selected rule. | Required | 

#### Context Output

There is no context output for this command.
### incap-add-site-datacenter

***
Use this operation to add a data center to a site.

#### Base Command

`incap-add-site-datacenter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| name | The new data center's name. | Required | 
| server_address | The server's address. Possible values: IP, CNAME. | Required | 
| is_enabled | Enables the data center. Possible values are: true, false. | Optional | 
| is_content | The data center will be available for specific resources (Forward Delivery Rules). Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### incap-edit-site-datacenter

***
Use this operation to edit a site's data center.

#### Base Command

`incap-edit-site-datacenter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dc_id | The data center's ID. | Required | 
| name | The new data center's name. | Optional | 
| is_enabled | Enables the data center. Possible values are: true, false. | Optional | 
| is_standby | Defines the data center as standby for failover. Possible values are: true, false. | Optional | 
| is_content | The data center will be available for specific resources (Forward Delivery Rules). Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### incap-delete-site-datacenter

***
Use this operation to delete a site's data center.

#### Base Command

`incap-delete-site-datacenter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dc_id | The data center's ID. | Required | 

#### Context Output

There is no context output for this command.
### incap-list-site-datacenters

***
Use this operation to list a site's data centers including the data centers' servers.

#### Base Command

`incap-list-site-datacenters`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-add-site-datacenter-server

***
Use this operation to add a server to a data center.

#### Base Command

`incap-add-site-datacenter-server`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dc_id | The data center's ID. | Required | 
| server_address | The server's address. Possible values: IP, CNAME. | Required | 
| name | The new data center's name. | Optional | 
| is_standby | Set the server as Active (P0) or Standby (P1) (Boolean). Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### incap-edit-site-datacenter-server

***
Use this operation to add a server to a data center.

#### Base Command

`incap-edit-site-datacenter-server`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_id | Server ID. | Required | 
| server_address | The server's address. Possible values: IP, CNAME. | Required | 
| name | The new data center's name. | Optional | 
| is_enabled | Enable or disable the server (Boolean). Possible values are: true, false. | Optional | 
| is_standby | Set the server as Active (P0) or Standby (P1) (Boolean). Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### incap-delete-site-datacenter-server

***
Use this operation to delete a data center's server.

#### Base Command

`incap-delete-site-datacenter-server`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_id | Server ID. | Required | 

#### Context Output

There is no context output for this command.
### incap-get-statistics

***
Use this operation to get site statistics for one or more sites. This operation may return multiple statistics, as specified in the stats parameter

#### Base Command

`incap-get-statistics`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to fetch data for. If not specified, data will be fetched for all site of the account identified by the authentication parameters. | Optional | 
| time_range | Time range to fetch data for. See https://my.incapsula.com/api/docs/v1#timeRange. | Required | 
| start | Start date in milliseconds since 1970. See the introduction of the API documentation for a detailed description. | Optional | 
| end | End date in milliseconds since 1970. See the introduction of the API documentation for a detailed description. | Optional | 
| site_id | Numeric identifier of the site to fetch data for. Multiple sites can be specified in a comma separated list. For example: 123,124,125. | Optional | 
| stats | Statistics to fetch, see options at https://my.incapsula.com/api/docs/v1/data#getStats. | Required | 
| granularity | Time interval in milliseconds between data points for time series stats. Default is 86400000 (1 day) for a range of less than 30 days and 259200000 (3 days) for a range of less than 90 days. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-visits

***
Use this operation to get a log of recent visits to a website. The visits are fetched in reverse chronological order, starting with the most recent visit. Not all visits are recorded - only visits with abnormal activity are recorded e.g. violation of security rules, visits from black-listed IPs/Countries, etc. A visit may still be updated even after it was retrieved. To avoid retrieving such visits and to retrieve only visits that will no longer be updated use the list_live_visits parameter

#### Base Command

`incap-get-visits`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| time_range | Time range to fetch data for. Default is last_7_days. | Optional | 
| start | Start date in milliseconds since 1970. See the introduction of the API documentation for a detailed description. | Optional | 
| end | End date in milliseconds since 1970. See the introduction of the API documentation for a detailed description. | Optional | 
| page_size | The number of objects to return in the response. Defaults to 10. | Optional | 
| page_num | Filter the sessions that were handled according to the security-related specifications. Multiple values are supported, e.g.: "api.threats.action.block_ip, api.threats.sql_injection". | Optional | 
| country | Filter the sessions coming from the specified country. | Optional | 
| ip | Filter the sessions coming from the specified IP. | Optional | 
| visit_id | Comma separated list of visit IDs to load. | Optional | 
| list_live_visits | Whether or not to list visits that did not end and that may still be updated. One of: true \| false. Default: true. | Optional | 
| security | Filter the sessions that were handled according to the security-related specifications. Multiple values are supported, e.g.: "api.threats.action.block_ip, api.threats.sql_injection". | Optional | 

#### Context Output

There is no context output for this command.
### incap-upload-public-key

***
Organizations that purchased the Security Logs Integration SKU can download security events created for their account and archive or push those events into their SIEM solution

#### Base Command

`incap-upload-public-key`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | The Logs Collector configuration identifier. | Required | 
| public_key | The public key file(2048bit) in base64 format (without password protection). | Required | 

#### Context Output

There is no context output for this command.
### incap-change-logs-collector-configuration

***
Available only for Enterprise Plan customers that purchased the Security Logs Integration SKU.  Use this operation to change the status of the Logs Collector configuration

#### Base Command

`incap-change-logs-collector-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | The Logs Collector configuration identifier. | Required | 
| logs_config_new_status | The new configuration status of the Logs Collector. Values can be ACTIVE or SUSPENDED. | Required | 

#### Context Output

There is no context output for this command.
### incap-get-infra-protection-statistics

***
Use this operation to get Infrastructure Protection statistics for an account or IP range.

#### Base Command

`incap-get-infra-protection-statistics`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 
| ip_prefix | Specific Protected IP or IP range. For example, 1.1.1.0/24. | Optional | 
| traffic | Specific traffic. One of: Total, Passed, Blocked. Possible values are: Total, Passed, Blocked. | Optional | 
| traffic_type | A comma separated list of specific traffic types. Any of: UDP, TCP, DNS, DNS_RESPONSE, ICMP, SYN, FRAG, LARGE_SYN, NTP, NETFLOW, SSDP, GENERAL. Cannot be used together with the pop parameter. | Optional | 
| pop | A comma separated list of specific PoP names. For example: iad, tko. Cannot be used together with the traffic_type parameter. For the list of PoP codes and locations, see https://docs.incapsula.com/Content/read-more/pops.htm. | Optional | 
| start | The start date in milliseconds, since 1970. For a detailed description, see https://docs.incapsula.com/Content/API/api.htm. | Optional | 
| end | The end date in milliseconds, since 1970. For a detailed description, see https://docs.incapsula.com/Content/API/api.htm. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Imperva.EventStats.stats.payload.ipPrefix | string | IP prefix | 
| Imperva.EventStats.stats.payload.ipPrefixType | string | IP prefix type | 
| Imperva.EventStats.stats.payload.traffic | unknown | Traffic state, such as blocked or passed | 

### incap-get-infra-protection-events

***
Use this operation to get Infrastructure Protection event information for an account.

#### Base Command

`incap-get-infra-protection-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. If not specified, operation will be performed on the account identified by the authentication parameters. | Optional | 
| event_type | A comma separated list of specific event types. Any of: GRE_TUNNEL_UP, GRE_TUNNEL_DOWN, ORIGIN_CONNECTION_GRE_UP, ORIGIN_CONNECTION_GRE_DOWN, ORIGIN_CONNECTION_ECX_UP, ORIGIN_CONNECTION_ECX_DOWN, ORIGIN_CONNECTION_CROSS_CONNECT_UP, ORIGIN_CONNECTION_CROSS_CONNECT_DOWN, DDOS_START_IP_RANGE, DDOS_STOP_IP_RANGE, DDOS_QUIET_TIME_IP_RANGE, EXPORTER_NO_DATA, EXPORTER_BAD_DATA, EXPORTER_GOOD_DATA, MONITORING_CRITICAL_ATTACK, PROTECTED_IP_STATUS_UP, PROTECTED_IP_STATUS_DOWN, PER_IP_DDOS_START_IP_RANGE. | Optional | 
| ip_prefix | Specific Protected IP or IP range. For example, 1.1.1.0/24. | Optional | 
| page_size | The number of objects to return in the response.<br/>Default: 50<br/>Maximum: 100. | Optional | 
| page_num | The page to return starting from 0. Default: 0. | Optional | 
| start | The start date in milliseconds, since 1970. For a detailed description, see https://docs.incapsula.com/Content/API/api.htm. | Optional | 
| end | The end date in milliseconds, since 1970. For a detailed description, see https://docs.incapsula.com/Content/API/api.htm. | Optional | 

#### Context Output

There is no context output for this command.
### incap-add-login-protect

***
Use this operation to add Login Protect user for site

#### Base Command

`incap-add-login-protect`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 
| email | E-mail address, for example: "joe@example.com". | Required | 
| name | Example: John Smith. | Optional | 
| phone | Phone number, country code - number, for example: "1-8662507659". | Optional | 
| is_email_verified | Whether or not to skip E-Mail address verificaion. | Optional | 
| is_phone_verified | Whether or not to skip phone address verificaion. | Optional | 
| should_send_activation_email | Whether or not to send activation E-Mail to user. | Optional | 

#### Context Output

There is no context output for this command.
### incap-edit-login-protect

***
Use this operation to edit Login Protect user's settings

#### Base Command

`incap-edit-login-protect`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 
| email | E-mail address, for example: "joe@example.com". | Required | 
| name | Example: John Smith. | Optional | 
| phone | Phone number, country code - number, for example: "1-8662507659". | Optional | 
| is_email_verified | Whether or not to skip E-Mail address verificaion. | Optional | 
| is_phone_verified | Whether or not to skip phone address verificaion. | Optional | 
| should_send_activation_email | Whether or not to send activation E-Mail to user. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-login-protect

***
Use this operation to get the account's login protect user list

#### Base Command

`incap-get-login-protect`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 

#### Context Output

There is no context output for this command.
### incap-remove-login-protect

***
Use this operation to remove login protect user from account's user list

#### Base Command

`incap-remove-login-protect`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 
| email | E-mail address, for example: "joe@example.com". | Required | 

#### Context Output

There is no context output for this command.
### incap-send-sms-to-user

***
Use this operation to send SMS to login protect user

#### Base Command

`incap-send-sms-to-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Numeric identifier of the account to operate on. | Required | 
| email | E-mail address, for example: "joe@example.com". | Optional | 
| sms_text | Text that will be sent in SMS. | Optional | 

#### Context Output

There is no context output for this command.
### incap-modify-login-protect

***
Use this operation to change Login Protect settings for site

#### Base Command

`incap-modify-login-protect`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| enabled | Pass true to enable login protect on site, and false to disable it. Default is true. | Optional | 
| specific_users_list | Comma seperated E-Mail list to set login protect users for the site, if the list is empty all users will be allowed to access the site using Login Protect. | Optional | 
| send_lp_notifications | Pass true to send notification on successful login using login protect. Default is false. | Optional | 
| allow_all_users | Pass true to allow all login protect users to access the site. If you choose to allow only spesific list of users to access the site using Login Protect set this to false, and add the list to specific_user_list. Default value is true. | Optional | 
| authentication_methods | Comma seperated list of allowed authentication methods sms \| email \| ga. | Optional | 
| urls | A comma separated list of resource paths. For example, /home and /admin/index.html are resource paths, however http://www.example.com/home is not. Each URL should be encoded separately using percent encoding as specified by RFC 3986 (http://tools.ietf.org/html/rfc3986#section-2.1). An empty URL list will remove all URLs. | Optional | 
| url_patterns | A comma seperated list of url patterns, one of: contains \| equals \| prefix \| suffix \| not_equals \| not_contain \| not_prefix \| not_suffix. The patterns should be in accordance with the matching urls sent by the urls parameter. | Optional | 

#### Context Output

There is no context output for this command.
### incap-configure-app

***
Use this operation to configure Login Protect on wordpress | joomla | phpbb admin areas

#### Base Command

`incap-configure-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Numeric identifier of the site to operate on. | Required | 
| protected_app | Protect admin areas of joomla \| wordpress \| phpBB. | Optional | 

#### Context Output

There is no context output for this command.
### incap-get-ip-ranges

***
Use this operation to get the updated list of Incapsula IP ranges

#### Base Command

`incap-get-ip-ranges`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### incap-get-texts

***
Use this operation to retrieve a list of all text messages that may be part of API responses

#### Base Command

`incap-get-texts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### incap-get-geo-info

***
Use this operation to retrieve a list of all the countries and continents codes

#### Base Command

`incap-get-geo-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### incap-get-app-info

***
Use this operation to retrieve a list of all the client applications

#### Base Command

`incap-get-app-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### incap-get-infra-protection-top-items-table

***
Use this operation to view the highest peak values and highest average values for a protected IP range during a selected time period

#### Base Command

`incap-get-infra-protection-top-items-table`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_range | The customer's IP range. | Required | 
| range_type | One of the following: BGP, NETFLOW, PROTECTED_IP. Possible values are: BGP, NETFLOW, PROTECTED_IP. | Required | 
| start | The start date in milliseconds, since 1970. | Required | 
| end | The end date in milliseconds, since 1970. | Required | 
| data_type | One of the following: SRC_IP, DST_IP, SRC_PORT_PROTOCOL, DST_PORT_PROTOCOL. Possible values are: SRC_IP, DST_IP, SRC_PORT_PROTOCOL, DST_PORT_PROTOCOL. | Required | 
| metric_type | One of the following: BW, PPS. Possible values are: BW, PPS. | Required | 
| mitigation_type | One of the following: BLOCK, PASS. Possible values are: BLOCK, PASS. | Required | 
| aggregation_type | One of the following: PEAK, AVERAGE. Possible values are: PEAK, AVERAGE. | Required | 

#### Context Output

There is no context output for this command.