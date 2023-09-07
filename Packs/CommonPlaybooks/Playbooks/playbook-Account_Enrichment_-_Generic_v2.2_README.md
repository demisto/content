Enrich accounts using one or more integrations.
Supported integrations:
- Active Directory
- SailPoint IdentityNow
- SailPoint IdentityIQ
- PingOne
- Okta
- AWS IAM
- Cortex XDR (account enrichment and reputation)

Also, the playbook supports the generic command 'iam-get-user' (implemented in IAM integrations. For more information, visit https://xsoar.pan.dev/docs/integrations/iam-integrations.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Active Directory - Get User Manager Details

### Integrations

This playbook does not use any integrations.

### Scripts

* IsIntegrationAvailable
* Set
* SetAndHandleEmpty

### Commands

* okta-get-user
* msgraph-user-get
* identityiq-search-identities
* aws-iam-get-user
* ad-get-user
* pingone-get-user
* msgraph-user-get-manager
* iam-get-user
* xdr-list-risky-users
* identitynow-get-accounts

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Username | The usernames to enrich. This input supports multiple usernames.<br/>Usernames can be with or without a domain prefix, in the format of "username" or "domain\\username".<br/>Domain usernames will only be enriched in integrations that support  them. | Account.Username | Optional |
| Domain | Optional - This input is needed for the IAM-get-user command \(used in the Account Enrichment - IAM playbook\). Please provide the domain name that the user is related to.<br/>Example: @xsoar.com |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | The account object. | string |
| ActiveDirectory.Users.sAMAccountName | The user's SAM account name. | string |
| ActiveDirectory.Users.userAccountControl | The user's account control flag. | string |
| ActiveDirectory.Users.mail | The user's email address. | string |
| ActiveDirectory.Users.memberOf | Groups the user is a member of. | string |
| IAM | Generic IAM output. | string |
| IdentityIQ.Identity | Identity asset from IdentityIQ. | string |
| PingOne.Account | Account in PingID. | string |
| ActiveDirectory.Users.manager | The manager of the user. | string |
| IAM.Vendor.active | When true, indicates that the employee's status is active in the 3rd-party integration. | string |
| IAM.Vendor.brand | Name of the integration. | string |
| IAM.Vendor.details | Provides the raw data from the 3rd-party integration. | string |
| IAM.Vendor.email | The employee's email address. | string |
| IAM.Vendor.errorCode | HTTP error response code. | string |
| IAM.Vendor.errorMessage | Reason why the API failed. | string |
| IAM.Vendor.id | The employee's user ID in the app. | string |
| IAM.Vendor.instanceName | Name of the integration instance. | string |
| IAM.Vendor.success | When true, indicates that the command was executed successfully. | string |
| IAM.Vendor.username | The employee's username in the app. | string |
| IdentityIQ.Identity.userName | The IdentityIQ username \(primary ID\). | string |
| IdentityIQ.Identity.id | The IdentityIQ internal ID \(UUID\). | string |
| IdentityIQ.Identity.active | Indicates whether the ID is active or inactive in IdentityIQ. | string |
| IdentityIQ.Identity.lastModified | Timestamp of when the identity was last modified. | string |
| IdentityIQ.Identity.displayName | The display name of the identity. | string |
| IdentityIQ.Identity.emails | Array of email objects. | string |
| IdentityIQ.Identity.entitlements | Array of entitlement objects that the identity has. | string |
| IdentityIQ.Identity.roles | Array of role objects that the identity has. | string |
| IdentityIQ.Identity.capabilities | Array of string representations of the IdentityIQ capabilities assigned to this identity. | string |
| IdentityIQ.Identity.name | Account name. | string |
| IdentityIQ.Identity.name.formatted | The display name of the identity. | string |
| IdentityIQ.Identity.name.familyName | The last name of the identity. | string |
| IdentityIQ.Identity.name.givenName | The first name of the identity. | string |
| IdentityIQ.Identity.manager | The account's manager returned from IdentityIQ. | string |
| IdentityIQ.Identity.manager.userName | The IdentityIQ username \(primary ID\) of the identity's manager. | string |
| IdentityIQ.Identity.emails.type | Type of the email being returned. | string |
| IdentityIQ.Identity.emails.value | The email address of the identity. | string |
| IdentityIQ.Identity.emails.primary | Indicates if this email address is the identity's primary email. | string |
| PingOne.Account.ID | PingOne account ID. | string |
| PingOne.Account.Username | PingOne account username. | string |
| PingOne.Account.DisplayName | PingOne account display name. | string |
| PingOne.Account.Email | PingOne account email. | string |
| PingOne.Account.Enabled | PingOne account enabled status. | string |
| PingOne.Account.CreatedAt | PingOne account create date. | string |
| PingOne.Account.UpdatedAt | PingOne account updated date. | string |
| Account.PasswordChanged | Timestamp for when the user's password was last changed. | string |
| Account.StatusChanged | Timestamp for when the user's status was last changed. | string |
| Account.Activated | Timestamp for when the user was activated. | string |
| Account.Created | Timestamp for when the user was created. | string |
| Account.Status | Okta account status. | string |
| Account.Username | The user SAM account name. | string |
| Account.Email | The user email address. | string |
| Account.ID | The user distinguished name. | string |
| ActiveDirectory.Users.dn | The user distinguished name. | string |
| ActiveDirectory.Users.displayName | The user display name. | string |
| ActiveDirectory.Users.name | The user common name. | string |
| ActiveDirectory.Users.userAccountControlFields | The user account control fields. | string |
| ActiveDirectory.Users.userAccountControlFields.SCRIPT | Whether the login script is run. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.ACCOUNTDISABLE | Whether the user account is disabled. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.HOMEDIR_REQUIRED | Whether the home folder is required. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.LOCKOUT | Whether the user is locked out. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.PASSWD_NOTREQD | Whether the password is required. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.PASSWD_CANT_CHANGE | Whether the user can change the password. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.ENCRYPTED_TEXT_PWD_ALLOWED | Whether the user can send an encrypted password. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.TEMP_DUPLICATE_ACCOUNT | Whether this is an account for users whose primary account is in another domain. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.NORMAL_ACCOUNT | Whether this is a default account type that represents a typical user. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.INTERDOMAIN_TRUST_ACCOUNT | Whether the account is permitted to trust a system domain that trusts other domains. Works for \*Windows Server 2012 R2\*. | string |
| ActiveDirectory.Users.userAccountControlFields.WORKSTATION_TRUST_ACCOUNT | Whether this is a computer account for a computer running Microsoft Windows NT 4.0 Workstation, Microsoft Windows NT 4.0 Server, Microsoft Windows 2000 Professional, or Windows 2000 Server and is a member of this domain. | string |
| Account.Manager | The user manager. | string |
| Account.Groups | Groups for which the user is a member. | string |
| Account.DisplayName | The user display name. | string |
| ActiveDirectory.Users.userAccountControlFields.PARTIAL_SECRETS_ACCOUNT | Whether the account is a read-only domain controller \(RODC\). | string |
| ActiveDirectory.Users.userAccountControlFields.TRUSTED_TO_AUTH_FOR_DELEGATION | Whether the account is enabled for delegation. | string |
| ActiveDirectory.Users.userAccountControlFields.DONT_REQ_PREAUTH | Whether this account require Kerberos pre-authentication for logging on. | string |
| ActiveDirectory.Users.userAccountControlFields.USE_DES_KEY_ONLY | Whether to restrict this principal to use only Data Encryption Standard \(DES\) encryption types for keys. | string |
| ActiveDirectory.Users.userAccountControlFields.NOT_DELEGATED | Whether the security context of the user isn't delegated to a service even if the service account is set as trusted for Kerberos delegation. | string |
| ActiveDirectory.Users.userAccountControlFields.TRUSTED_FOR_DELEGATION | Whether the service account \(the user or computer account\) under which a service runs is trusted for Kerberos delegation. | string |
| ActiveDirectory.Users.userAccountControlFields.SMARTCARD_REQUIRED | Whether to force the user to log in by using a smart card. | string |
| ActiveDirectory.Users.userAccountControlFields.MNS_LOGON_ACCOUNT | Whether this is an MNS login account. | string |
| ActiveDirectory.Users.userAccountControlFields.SERVER_TRUST_ACCOUNT | Whether this is a computer account for a domain controller that is a member of this domain. Works for \*Windows Server 2012 R2\*. | string |
| IAM.Vendor | The returning results vendor. | string |
| IAM.Vendor.action | The command name. | string |
| IAM.UserProfile | The user profile. | string |
| SailPointIdentityNow.Account | The IdentityNow account object. | string |
| SailPointIdentityNow.Account.id | The IdentityNow internal ID \(UUID\). | string |
| SailPointIdentityNow.Account.name | Name of the identity on this account. | string |
| SailPointIdentityNow.Account.identityId | The IdentityNow internal identity ID. | string |
| SailPointIdentityNow.Account.nativeIdentity | The IdentityNow internal native identity ID. | string |
| SailPointIdentityNow.Account.sourceId | Source ID that maps this account. | string |
| SailPointIdentityNow.Account.created | Timestamp when the account was created. | string |
| SailPointIdentityNow.Account.modified | Timestamp when the account was last modified. | string |
| SailPointIdentityNow.Account.attributes | Map of variable number of attributes unique to this account. | string |
| SailPointIdentityNow.Account.authoritative | Indicates whether the account is the true source for this identity. | string |
| SailPointIdentityNow.Account.disabled | Indicates whether the account is disabled. | string |
| SailPointIdentityNow.Account.locked | Indicates whether the account is locked. | string |
| SailPointIdentityNow.Account.systemAccount | Indicates whether the account is a system account. | string |
| SailPointIdentityNow.Account.uncorrelated | Indicates whether the account is uncorrelated. | string |
| SailPointIdentityNow.Account.manuallyCorrelated | Indicates whether the account was manually correlated. | string |
| SailPointIdentityNow.Account.hasEntitlements | Indicates whether the account has entitlement. | string |
| UserManagerEmail | The email of the user's manager. | string |
| UserManagerDisplayName | The display name of the user's manager. | string |
| MSGraphUser.ID | User's ID. | string |
| MSGraphUser.DisplayName | User's display name. | string |
| MSGraphUser.GivenName | User's given name. | string |
| MSGraphUser.JobTitle | User's job title. | string |
| MSGraphUser.Mail | User's mail address. | string |
| MSGraphUser.Surname | User's surname. | string |
| MSGraphUser.UserPrincipalName | User's principal name. | string |
| MSGraphUserManager.Manager.ID | Manager's user ID. | string |
| MSGraphUserManager.Manager.DisplayName | User's display name. | string |
| MSGraphUserManager.Manager.GivenName | User's given name. | string |
| MSGraphUserManager.Manager.Mail | User's mail address. | string |
| MSGraphUserManager.Manager.Surname | User's surname. | string |
| MSGraphUserManager.Manager.UserPrincipalName | User's principal name. | string |
| PaloAltoNetworksXDR.RiskyUser | The account object. | string |
| PaloAltoNetworksXDR.RiskyUser.type | Form of identification element. | string |
| PaloAltoNetworksXDR.RiskyUser.id | Identification value of the type field. | string |
| PaloAltoNetworksXDR.RiskyUser.score | The score assigned to the user. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons | The account risk objects. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.date created | Date when the incident was created. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.description | Description of the incident. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.severity | The severity of the incident | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.status | The incident status | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.points | The score. | string |

## Playbook Image

---

![Account Enrichment - Generic v2.1](../doc_files/Account_Enrichment_-_Generic_v2.1.png)
